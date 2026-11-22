use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ROUNDS: usize = 16;

const INIT_CONSTS: [u64; 4] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
];

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
const ROUND_SALT: u64 = 0x517C_C1B7_2722_0A95;

fn xtime_ct(x: u8) -> u8 {
    let mask = 0u8.wrapping_sub(x >> 7);
    (x << 1) ^ (0x1B & mask)
}

fn gmul_ct(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        let mask_b = 0u8.wrapping_sub(b & 1);
        res ^= a & mask_b;
        a = xtime_ct(a);
        b >>= 1;
    }
    res
}

fn ginv_ct(a: u8) -> u8 {
    let a2 = gmul_ct(a, a);
    let a3 = gmul_ct(a2, a);
    let a6 = gmul_ct(a3, a3);
    let a12 = gmul_ct(a6, a6);
    let a15 = gmul_ct(a12, a3);
    let a30 = gmul_ct(a15, a15);
    let a60 = gmul_ct(a30, a30);
    let a120 = gmul_ct(a60, a60);
    let a126 = gmul_ct(a120, a6);
    let a127 = gmul_ct(a126, a);
    gmul_ct(a127, a127)
}

fn sbox_ct(x: u8) -> u8 {
    let y = ginv_ct(x);
    y ^ y.rotate_left(1) ^ y.rotate_left(2) ^ y.rotate_left(3) ^ y.rotate_left(4) ^ 0x63
}

fn inv_sbox_ct(x: u8) -> u8 {
    let y = x.rotate_left(1) ^ x.rotate_left(3) ^ x.rotate_left(6) ^ 0x05;
    ginv_ct(y)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Knox256 {
    keys: [[u64; 2]; ROUNDS + 1],
    #[zeroize(skip)]
    use_aesni: bool,
}

impl Knox256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut st = [
            read_u64(&key[0..8]) ^ INIT_CONSTS[0],
            read_u64(&key[8..16]) ^ INIT_CONSTS[1],
            read_u64(&key[16..24]) ^ INIT_CONSTS[2],
            read_u64(&key[24..32]) ^ INIT_CONSTS[3],
        ];

        let mut keys = [[0u64; 2]; ROUNDS + 1];

        for r in 0..=ROUNDS {
            let rc = GOLDEN.wrapping_mul((r as u64).wrapping_add(1));

            for step in 0..4 {
                st[0] = st[0].wrapping_add(st[1]).wrapping_add(rc ^ (step as u64));
                st[1] = st[1].rotate_left(17) ^ st[0];
                st[2] = st[2].wrapping_add(st[3]);
                st[3] = st[3].rotate_left(29) ^ st[2];

                st[0] = st[0].wrapping_add(st[3]);
                st[3] = st[3].rotate_left(41) ^ st[0];
                st[2] = st[2].wrapping_add(st[1]);
                st[1] = st[1].rotate_left(11) ^ st[2];

                let idx = step & 3;
                let mut bytes = st[idx].to_le_bytes();
                for j in 0..8 {
                    bytes[j] = sbox_ct(bytes[j]);
                }
                st[idx] = u64::from_le_bytes(bytes).rotate_left(13);
            }

            keys[r] = [st[0] ^ st[2], st[1] ^ st[3]];
        }

        st.zeroize();

        #[cfg(target_arch = "x86_64")]
        let use_aesni = is_x86_feature_detected!("aes");
        #[cfg(not(target_arch = "x86_64"))]
        let use_aesni = false;

        Self { keys, use_aesni }
    }

    pub fn backend_name(&self) -> &'static str {
        if self.use_aesni {
            "AES-NI"
        } else {
            "CT-SW"
        }
    }

    pub fn encrypt_block(&self, state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            #[allow(unsafe_code)]
            unsafe {
                return self.encrypt_block_aesni(state, tweak);
            }
        }
        self.encrypt_block_ct(state, tweak)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    #[allow(unsafe_code)]
    unsafe fn encrypt_block_aesni(&self, state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        use std::arch::x86_64::*;

        let tw = split_tweak(tweak);
        let zero = _mm_setzero_si128();
        let mut l = read_u64(&state[0..8]) ^ self.keys[0][0];
        let mut r = read_u64(&state[8..16]) ^ self.keys[0][1];

        for round in 1..=ROUNDS {
            let v = _mm_set_epi64x(r as i64, l as i64);
            let mixed = _mm_aesenc_si128(v, zero);
            l = _mm_cvtsi128_si64(mixed) as u64;
            r = _mm_cvtsi128_si64(_mm_unpackhi_epi64(mixed, mixed)) as u64;

            let tw_word = tw[round % 3].wrapping_add((round as u64).wrapping_mul(ROUND_SALT));
            l = l.wrapping_add(r);
            r = r.rotate_left(13) ^ l;
            r = r.wrapping_add(tw_word);
            l = l.rotate_left(31) ^ r;

            l ^= self.keys[round][0];
            r ^= self.keys[round][1];
        }

        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&l.to_le_bytes());
        out[8..16].copy_from_slice(&r.to_le_bytes());
        out
    }

    pub fn encrypt_block_ct(&self, mut state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        let tw = split_tweak(tweak);
        xor_key(&mut state, &self.keys[0]);

        for round in 1..=ROUNDS {
            sub_bytes_ct(&mut state);
            shift_rows(&mut state);
            mix_columns_ct(&mut state);
            let tw_word = tw[round % 3].wrapping_add((round as u64).wrapping_mul(ROUND_SALT));
            arx_mix(&mut state, tw_word);
            xor_key(&mut state, &self.keys[round]);
        }

        state
    }

    #[allow(dead_code)]
    pub fn decrypt_block(&self, mut state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        let tw = split_tweak(tweak);

        for round in (1..=ROUNDS).rev() {
            xor_key(&mut state, &self.keys[round]);
            let tw_word = tw[round % 3].wrapping_add((round as u64).wrapping_mul(ROUND_SALT));
            inv_arx_mix(&mut state, tw_word);
            inv_mix_columns_ct(&mut state);
            inv_shift_rows(&mut state);
            inv_sub_bytes_ct(&mut state);
        }

        xor_key(&mut state, &self.keys[0]);
        state
    }
}

fn read_u64(slice: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    u64::from_le_bytes(buf)
}

fn split_tweak(tweak: [u8; 16]) -> [u64; 3] {
    let t0 = read_u64(&tweak[0..8]);
    let t1 = read_u64(&tweak[8..16]);
    [t0, t1, t0 ^ t1 ^ GOLDEN]
}

fn xor_key(s: &mut [u8; 16], k: &[u64; 2]) {
    let l = read_u64(&s[0..8]) ^ k[0];
    let r = read_u64(&s[8..16]) ^ k[1];
    s[0..8].copy_from_slice(&l.to_le_bytes());
    s[8..16].copy_from_slice(&r.to_le_bytes());
}

fn sub_bytes_ct(s: &mut [u8; 16]) {
    for i in 0..16 {
        s[i] = sbox_ct(s[i]);
    }
}

fn inv_sub_bytes_ct(s: &mut [u8; 16]) {
    for i in 0..16 {
        s[i] = inv_sbox_ct(s[i]);
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    s.swap(2, 10);
    s.swap(6, 14);

    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;

    s.swap(2, 10);
    s.swap(6, 14);

    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

fn mix_columns_ct(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = s[i];
        let b = s[i + 1];
        let c = s[i + 2];
        let d = s[i + 3];
        let t = a ^ b ^ c ^ d;

        s[i] = a ^ t ^ xtime_ct(a ^ b);
        s[i + 1] = b ^ t ^ xtime_ct(b ^ c);
        s[i + 2] = c ^ t ^ xtime_ct(c ^ d);
        s[i + 3] = d ^ t ^ xtime_ct(d ^ a);
    }
}

fn inv_mix_columns_ct(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = s[i];
        let b = s[i + 1];
        let c = s[i + 2];
        let d = s[i + 3];

        let u = xtime_ct(xtime_ct(a ^ c));
        let v = xtime_ct(xtime_ct(b ^ d));

        s[i] ^= u;
        s[i + 1] ^= v;
        s[i + 2] ^= u;
        s[i + 3] ^= v;
    }
    mix_columns_ct(s);
}

fn arx_mix(s: &mut [u8; 16], tw: u64) {
    let mut l = read_u64(&s[0..8]);
    let mut r = read_u64(&s[8..16]);

    l = l.wrapping_add(r);
    r = r.rotate_left(13) ^ l;
    r = r.wrapping_add(tw);
    l = l.rotate_left(31) ^ r;

    s[0..8].copy_from_slice(&l.to_le_bytes());
    s[8..16].copy_from_slice(&r.to_le_bytes());
}

fn inv_arx_mix(s: &mut [u8; 16], tw: u64) {
    let mut l = read_u64(&s[0..8]);
    let mut r = read_u64(&s[8..16]);

    l = (l ^ r).rotate_right(31);
    r = r.wrapping_sub(tw);
    r = (r ^ l).rotate_right(13);
    l = l.wrapping_sub(r);

    s[0..8].copy_from_slice(&l.to_le_bytes());
    s[8..16].copy_from_slice(&r.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_ct() {
        assert_eq!(sbox_ct(0x00), 0x63);
        assert_eq!(sbox_ct(0x01), 0x7C);
        assert_eq!(sbox_ct(0x02), 0x77);
        for i in 0..=255u8 {
            assert_eq!(inv_sbox_ct(sbox_ct(i)), i);
        }
    }

    #[test]
    fn test_block_roundtrip_and_backend_match() {
        let key = [0x42u8; 32];
        let tweak = [0x13u8; 16];
        let pt = *b"KNOX-256-HYBRID!";
        let cipher = Knox256::new(&key);

        let ct = cipher.encrypt_block(pt, tweak);
        let ct_sw = cipher.encrypt_block_ct(pt, tweak);
        assert_eq!(ct, ct_sw);
        assert_ne!(ct, pt);
        assert_eq!(cipher.decrypt_block(ct, tweak), pt);
    }

    #[test]
    fn test_avalanche() {
        let cipher = Knox256::new(&[0xA5u8; 32]);
        let tweak = [0x5Au8; 16];
        let p1 = [0u8; 16];
        let mut p2 = p1;
        p2[0] ^= 1;

        let c1 = cipher.encrypt_block(p1, tweak);
        let c2 = cipher.encrypt_block(p2, tweak);

        let mut diff = 0u32;
        for i in 0..16 {
            diff += (c1[i] ^ c2[i]).count_ones();
        }
        assert!(diff >= 44 && diff <= 84);
    }
}
