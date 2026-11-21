use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ROUNDS: usize = 16;

const SBOX: [u8; 256] = make_sbox();
const INV_SBOX: [u8; 256] = make_inv_sbox(&SBOX);

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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Knox256 {
    keys: [[u8; 16]; ROUNDS + 1],
}

impl Knox256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut st = [
            read_u64(&key[0..8]) ^ INIT_CONSTS[0],
            read_u64(&key[8..16]) ^ INIT_CONSTS[1],
            read_u64(&key[16..24]) ^ INIT_CONSTS[2],
            read_u64(&key[24..32]) ^ INIT_CONSTS[3],
        ];

        let mut keys = [[0u8; 16]; ROUNDS + 1];

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

            let lo = (st[0] ^ st[2]).to_le_bytes();
            let hi = (st[1] ^ st[3]).to_le_bytes();
            keys[r][0..8].copy_from_slice(&lo);
            keys[r][8..16].copy_from_slice(&hi);
        }

        st.zeroize();
        Self { keys }
    }

    pub fn encrypt_block(&self, mut state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        let tw = split_tweak(tweak);
        xor_key(&mut state, &self.keys[0]);

        for r in 1..=ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            let tw_word = tw[r % 3].wrapping_add((r as u64).wrapping_mul(ROUND_SALT));
            arx_mix(&mut state, tw_word);
            xor_key(&mut state, &self.keys[r]);
        }

        state
    }

    #[allow(dead_code)]
    pub fn decrypt_block(&self, mut state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        let tw = split_tweak(tweak);

        for r in (1..=ROUNDS).rev() {
            xor_key(&mut state, &self.keys[r]);
            let tw_word = tw[r % 3].wrapping_add((r as u64).wrapping_mul(ROUND_SALT));
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

fn xor_key(s: &mut [u8; 16], k: &[u8; 16]) {
    for i in 0..16 {
        s[i] ^= k[i];
    }
}

fn sub_bytes(s: &mut [u8; 16]) {
    for i in 0..16 {
        s[i] = SBOX[s[i] as usize];
    }
}

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for i in 0..16 {
        s[i] = INV_SBOX[s[i] as usize];
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

fn mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = s[i];
        let b = s[i + 1];
        let c = s[i + 2];
        let d = s[i + 3];

        s[i] = gmul(2, a) ^ gmul(3, b) ^ c ^ d;
        s[i + 1] = a ^ gmul(2, b) ^ gmul(3, c) ^ d;
        s[i + 2] = a ^ b ^ gmul(2, c) ^ gmul(3, d);
        s[i + 3] = gmul(3, a) ^ b ^ c ^ gmul(2, d);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = s[i];
        let b = s[i + 1];
        let c = s[i + 2];
        let d = s[i + 3];

        s[i] = gmul(14, a) ^ gmul(11, b) ^ gmul(13, c) ^ gmul(9, d);
        s[i + 1] = gmul(9, a) ^ gmul(14, b) ^ gmul(11, c) ^ gmul(13, d);
        s[i + 2] = gmul(13, a) ^ gmul(9, b) ^ gmul(14, c) ^ gmul(11, d);
        s[i + 3] = gmul(11, a) ^ gmul(13, b) ^ gmul(9, c) ^ gmul(14, d);
    }
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
