use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ROUNDS: usize = 16;

const SBOX: [u8; 256] = make_sbox();
const INV_SBOX: [u8; 256] = make_inv_sbox(&SBOX);

const T0: [u32; 256] = make_t_table(0);
const T1: [u32; 256] = make_t_table(1);
const T2: [u32; 256] = make_t_table(2);
const T3: [u32; 256] = make_t_table(3);

const GMUL9: [u8; 256] = make_gmul(9);
const GMUL11: [u8; 256] = make_gmul(11);
const GMUL13: [u8; 256] = make_gmul(13);
const GMUL14: [u8; 256] = make_gmul(14);

const INIT_CONSTS: [u64; 4] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
];

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
const ROUND_SALT: u64 = 0x517C_C1B7_2722_0A95;

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    let mut i = 0;
    while i < 8 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
        i += 1;
    }
    res
}

const fn ginv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gmul(res, base);
        }
        base = gmul(base, base);
        exp >>= 1;
    }
    res
}

const fn make_sbox() -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let x = ginv(i as u8);
        out[i] = x
            ^ x.rotate_left(1)
            ^ x.rotate_left(2)
            ^ x.rotate_left(3)
            ^ x.rotate_left(4)
            ^ 0x63;
        i += 1;
    }
    out
}

const fn make_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        out[sbox[i] as usize] = i as u8;
        i += 1;
    }
    out
}

const fn make_t_table(pos: usize) -> [u32; 256] {
    let mut out = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        let s2 = gmul(2, s);
        let s3 = gmul(3, s);
        let bytes = match pos {
            0 => [s2, s, s, s3],
            1 => [s3, s2, s, s],
            2 => [s, s3, s2, s],
            _ => [s, s, s3, s2],
        };
        out[i] = u32::from_le_bytes(bytes);
        i += 1;
    }
    out
}

const fn make_gmul(k: u8) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        out[i] = gmul(k, i as u8);
        i += 1;
    }
    out
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Knox256 {
    keys: [[u64; 2]; ROUNDS + 1],
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
                    bytes[j] = SBOX[bytes[j] as usize];
                }
                st[idx] = u64::from_le_bytes(bytes).rotate_left(13);
            }

            keys[r] = [st[0] ^ st[2], st[1] ^ st[3]];
        }

        st.zeroize();
        Self { keys }
    }

    pub fn encrypt_block(&self, state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        let tw = split_tweak(tweak);
        let mut l = read_u64(&state[0..8]) ^ self.keys[0][0];
        let mut r = read_u64(&state[8..16]) ^ self.keys[0][1];

        for round in 1..=ROUNDS {
            let a = l.to_le_bytes();
            let b = r.to_le_bytes();

            let c0 = T0[a[0] as usize] ^ T1[a[5] as usize] ^ T2[b[2] as usize] ^ T3[b[7] as usize];
            let c1 = T0[a[4] as usize] ^ T1[b[1] as usize] ^ T2[b[6] as usize] ^ T3[a[3] as usize];
            let c2 = T0[b[0] as usize] ^ T1[b[5] as usize] ^ T2[a[2] as usize] ^ T3[a[7] as usize];
            let c3 = T0[b[4] as usize] ^ T1[a[1] as usize] ^ T2[a[6] as usize] ^ T3[b[3] as usize];

            l = (c0 as u64) | ((c1 as u64) << 32);
            r = (c2 as u64) | ((c3 as u64) << 32);

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

    #[allow(dead_code)]
    pub fn decrypt_block(&self, mut state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        let tw = split_tweak(tweak);

        for round in (1..=ROUNDS).rev() {
            xor_key(&mut state, &self.keys[round]);
            let tw_word = tw[round % 3].wrapping_add((round as u64).wrapping_mul(ROUND_SALT));
            inv_arx_mix(&mut state, tw_word);
            inv_mix_columns(&mut state);
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
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

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for i in 0..16 {
        s[i] = INV_SBOX[s[i] as usize];
    }
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

fn inv_mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = s[i] as usize;
        let b = s[i + 1] as usize;
        let c = s[i + 2] as usize;
        let d = s[i + 3] as usize;

        s[i] = GMUL14[a] ^ GMUL11[b] ^ GMUL13[c] ^ GMUL9[d];
        s[i + 1] = GMUL9[a] ^ GMUL14[b] ^ GMUL11[c] ^ GMUL13[d];
        s[i + 2] = GMUL13[a] ^ GMUL9[b] ^ GMUL14[c] ^ GMUL11[d];
        s[i + 3] = GMUL11[a] ^ GMUL13[b] ^ GMUL9[c] ^ GMUL14[d];
    }
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
    fn test_sbox() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7C);
        assert_eq!(SBOX[0x02], 0x77);
        for i in 0..=255u8 {
            assert_eq!(INV_SBOX[SBOX[i as usize] as usize], i);
        }
    }

    #[test]
    fn test_block_roundtrip() {
        let key = [0x42u8; 32];
        let tweak = [0x13u8; 16];
        let pt = *b"KNOX-256-HYBRID!";
        let cipher = Knox256::new(&key);
        let ct = cipher.encrypt_block(pt, tweak);
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
