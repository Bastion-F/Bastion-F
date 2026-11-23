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
    #[zeroize(skip)]
    use_avx2: bool,
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

        #[cfg(target_arch = "x86_64")]
        let use_avx2 = use_aesni && is_x86_feature_detected!("avx2");
        #[cfg(not(target_arch = "x86_64"))]
        let use_avx2 = false;

        Self {
            keys,
            use_aesni,
            use_avx2,
        }
    }

    pub fn backend_name(&self) -> &'static str {
        if self.use_avx2 {
            "AVX2+AES-NI"
        } else if self.use_aesni {
            "AES-NI"
        } else {
            "CT-SW"
        }
    }

    pub fn encrypt_block(&self, state: [u8; 16], tweak: [u8; 16]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        if self.use_avx2 {
            #[allow(unsafe_code)]
            unsafe {
                return self.encrypt_chain_avx2(state, tweak, 1);
            }
        }
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            #[allow(unsafe_code)]
            unsafe {
                return self.encrypt_chain_aesni(state, tweak, 1);
            }
        }
        self.encrypt_block_ct(state, tweak)
    }

    pub fn encrypt_chain(&self, mut state: [u8; 16], tweak: [u8; 16], count: usize) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        if self.use_avx2 {
            #[allow(unsafe_code)]
            unsafe {
                return self.encrypt_chain_avx2(state, tweak, count);
            }
        }
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            #[allow(unsafe_code)]
            unsafe {
                return self.encrypt_chain_aesni(state, tweak, count);
            }
        }
        for _ in 0..count {
            state = self.encrypt_block_ct(state, tweak);
        }
        state
    }

    pub fn ctr_chunk(
        &self,
        stream_nonce: &[u8; 16],
        chunk_idx: u64,
        is_last: bool,
        data: &mut [u8],
    ) {
        #[cfg(target_arch = "x86_64")]
        if self.use_avx2 {
            #[allow(unsafe_code)]
            unsafe {
                self.ctr_chunk_avx2(stream_nonce, chunk_idx, is_last, data);
                return;
            }
        }
        #[cfg(target_arch = "x86_64")]
        if self.use_aesni {
            #[allow(unsafe_code)]
            unsafe {
                self.ctr_chunk_aesni(stream_nonce, chunk_idx, is_last, data);
                return;
            }
        }
        self.ctr_chunk_ct(stream_nonce, chunk_idx, is_last, data);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2,aes")]
    #[allow(unsafe_code)]
    unsafe fn encrypt_chain_avx2(
        &self,
        state: [u8; 16],
        tweak: [u8; 16],
        count: usize,
    ) -> [u8; 16] {
        use std::arch::x86_64::*;

        let zero = _mm_setzero_si128();
        let tw = split_tweak(tweak);

        let mut tw_r = [zero; ROUNDS];
        for r in 1..=ROUNDS {
            let w = tw[r % 3].wrapping_add((r as u64).wrapping_mul(ROUND_SALT));
            tw_r[r - 1] = _mm_cvtsi64_si128(w as i64);
        }

        let mut rk = [zero; ROUNDS + 1];
        for r in 0..=ROUNDS {
            rk[r] = _mm_loadu_si128(self.keys[r].as_ptr() as *const __m128i);
        }

        let mut v = _mm_loadu_si128(state.as_ptr() as *const __m128i);

        for _ in 0..count {
            v = _mm_xor_si128(v, rk[0]);
            for round in 1..=ROUNDS {
                let m = _mm_aesenc_si128(v, zero);
                let r0 = _mm_srli_si128::<8>(m);
                let l1 = _mm_add_epi64(m, r0);
                let r_rot = _mm_or_si128(_mm_slli_epi64::<13>(r0), _mm_srli_epi64::<51>(r0));
                let r1 = _mm_xor_si128(r_rot, l1);
                let r2 = _mm_add_epi64(r1, tw_r[round - 1]);
                let l_rot = _mm_or_si128(_mm_slli_epi64::<31>(l1), _mm_srli_epi64::<33>(l1));
                let l2 = _mm_xor_si128(l_rot, r2);
                v = _mm_xor_si128(_mm_unpacklo_epi64(l2, r2), rk[round]);
            }
        }

        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    #[allow(unsafe_code)]
    unsafe fn encrypt_chain_aesni(
        &self,
        state: [u8; 16],
        tweak: [u8; 16],
        count: usize,
    ) -> [u8; 16] {
        use std::arch::x86_64::*;

        let zero = _mm_setzero_si128();
        let tw = split_tweak(tweak);

        let mut tw_r = [zero; ROUNDS];
        for r in 1..=ROUNDS {
            let w = tw[r % 3].wrapping_add((r as u64).wrapping_mul(ROUND_SALT));
            tw_r[r - 1] = _mm_cvtsi64_si128(w as i64);
        }

        let mut rk = [zero; ROUNDS + 1];
        for r in 0..=ROUNDS {
            rk[r] = _mm_loadu_si128(self.keys[r].as_ptr() as *const __m128i);
        }

        let mut v = _mm_loadu_si128(state.as_ptr() as *const __m128i);

        for _ in 0..count {
            v = _mm_xor_si128(v, rk[0]);
            for round in 1..=ROUNDS {
                let m = _mm_aesenc_si128(v, zero);
                let r0 = _mm_srli_si128::<8>(m);
                let l1 = _mm_add_epi64(m, r0);
                let r_rot = _mm_or_si128(_mm_slli_epi64::<13>(r0), _mm_srli_epi64::<51>(r0));
                let r1 = _mm_xor_si128(r_rot, l1);
                let r2 = _mm_add_epi64(r1, tw_r[round - 1]);
                let l_rot = _mm_or_si128(_mm_slli_epi64::<31>(l1), _mm_srli_epi64::<33>(l1));
                let l2 = _mm_xor_si128(l_rot, r2);
                v = _mm_xor_si128(_mm_unpacklo_epi64(l2, r2), rk[round]);
            }
        }

        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2,aes")]
    #[allow(unsafe_code)]
    unsafe fn ctr_chunk_avx2(
        &self,
        stream_nonce: &[u8; 16],
        chunk_idx: u64,
        is_last: bool,
        data: &mut [u8],
    ) {
        use std::arch::x86_64::*;

        let zero = _mm_setzero_si128();
        let zero256 = _mm256_setzero_si256();
        let golden256 = _mm256_set1_epi64x(GOLDEN as i64);

        let base_lo = read_u64(&stream_nonce[0..8]);
        let base_mid = read_u32(&stream_nonce[8..12]);
        let last_mask = if is_last { 0xFFu8 } else { 0x00u8 };
        let hi_top = u32::from_le_bytes([
            stream_nonce[12],
            stream_nonce[13],
            stream_nonce[14],
            stream_nonce[15] ^ last_mask,
        ]) as u64;
        let hi_shifted = hi_top << 32;

        let t0 = base_lo ^ chunk_idx;
        let tw_t0 = _mm256_set1_epi64x(t0 as i64);

        let k0 = _mm_loadu_si128(self.keys[0].as_ptr() as *const __m128i);
        let mut kl = [zero256; ROUNDS + 1];
        let mut kr = [zero256; ROUNDS + 1];
        let mut rs = [zero256; ROUNDS];

        for r in 1..=ROUNDS {
            kl[r] = _mm256_set1_epi64x(self.keys[r][0] as i64);
            kr[r] = _mm256_set1_epi64x(self.keys[r][1] as i64);
            rs[r - 1] = _mm256_set1_epi64x((r as u64).wrapping_mul(ROUND_SALT) as i64);
        }

        let main_len = (data.len() / 128) * 128;
        let (main_data, rem) = data.split_at_mut(main_len);
        let mut b = 0u32;

        for chunk128 in main_data.chunks_exact_mut(128) {
            let mut v0 = _mm_xor_si128(
                _mm_set_epi64x(((b as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v1 = _mm_xor_si128(
                _mm_set_epi64x((((b + 1) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v2 = _mm_xor_si128(
                _mm_set_epi64x((((b + 2) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v3 = _mm_xor_si128(
                _mm_set_epi64x((((b + 3) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v4 = _mm_xor_si128(
                _mm_set_epi64x((((b + 4) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v5 = _mm_xor_si128(
                _mm_set_epi64x((((b + 5) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v6 = _mm_xor_si128(
                _mm_set_epi64x((((b + 6) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );
            let mut v7 = _mm_xor_si128(
                _mm_set_epi64x((((b + 7) as u64) | hi_shifted) as i64, chunk_idx as i64),
                                       k0,
            );

            let tw_a1 = _mm256_set_epi64x(
                (((base_mid ^ (b + 3)) as u64) | hi_shifted) as i64,
                                          (((base_mid ^ (b + 2)) as u64) | hi_shifted) as i64,
                                          (((base_mid ^ (b + 1)) as u64) | hi_shifted) as i64,
                                          (((base_mid ^ b) as u64) | hi_shifted) as i64,
            );
            let tw_b1 = _mm256_set_epi64x(
                (((base_mid ^ (b + 7)) as u64) | hi_shifted) as i64,
                                          (((base_mid ^ (b + 6)) as u64) | hi_shifted) as i64,
                                          (((base_mid ^ (b + 5)) as u64) | hi_shifted) as i64,
                                          (((base_mid ^ (b + 4)) as u64) | hi_shifted) as i64,
            );

            let tw_a2 = _mm256_xor_si256(_mm256_xor_si256(tw_t0, tw_a1), golden256);
            let tw_b2 = _mm256_xor_si256(_mm256_xor_si256(tw_t0, tw_b1), golden256);

            let tw_a = [tw_t0, tw_a1, tw_a2];
            let tw_b = [tw_t0, tw_b1, tw_b2];

            for round in 1..=ROUNDS {
                v0 = _mm_aesenc_si128(v0, zero);
                v1 = _mm_aesenc_si128(v1, zero);
                v2 = _mm_aesenc_si128(v2, zero);
                v3 = _mm_aesenc_si128(v3, zero);
                v4 = _mm_aesenc_si128(v4, zero);
                v5 = _mm_aesenc_si128(v5, zero);
                v6 = _mm_aesenc_si128(v6, zero);
                v7 = _mm_aesenc_si128(v7, zero);

                let y02 = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(v0), v2);
                let y13 = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(v1), v3);
                let y46 = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(v4), v6);
                let y57 = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(v5), v7);

                let mut la = _mm256_unpacklo_epi64(y02, y13);
                let mut ra = _mm256_unpackhi_epi64(y02, y13);
                let mut lb = _mm256_unpacklo_epi64(y46, y57);
                let mut rb = _mm256_unpackhi_epi64(y46, y57);

                let tw_ra = _mm256_add_epi64(tw_a[round % 3], rs[round - 1]);
                let tw_rb = _mm256_add_epi64(tw_b[round % 3], rs[round - 1]);

                la = _mm256_add_epi64(la, ra);
                lb = _mm256_add_epi64(lb, rb);

                let rot_ra = _mm256_or_si256(
                    _mm256_slli_epi64::<13>(ra),
                                             _mm256_srli_epi64::<51>(ra),
                );
                let rot_rb = _mm256_or_si256(
                    _mm256_slli_epi64::<13>(rb),
                                             _mm256_srli_epi64::<51>(rb),
                );
                ra = _mm256_xor_si256(rot_ra, la);
                rb = _mm256_xor_si256(rot_rb, lb);

                ra = _mm256_add_epi64(ra, tw_ra);
                rb = _mm256_add_epi64(rb, tw_rb);

                let rot_la = _mm256_or_si256(
                    _mm256_slli_epi64::<31>(la),
                                             _mm256_srli_epi64::<33>(la),
                );
                let rot_lb = _mm256_or_si256(
                    _mm256_slli_epi64::<31>(lb),
                                             _mm256_srli_epi64::<33>(lb),
                );
                la = _mm256_xor_si256(rot_la, ra);
                lb = _mm256_xor_si256(rot_lb, rb);

                la = _mm256_xor_si256(la, kl[round]);
                ra = _mm256_xor_si256(ra, kr[round]);
                lb = _mm256_xor_si256(lb, kl[round]);
                rb = _mm256_xor_si256(rb, kr[round]);

                let out02 = _mm256_unpacklo_epi64(la, ra);
                let out13 = _mm256_unpackhi_epi64(la, ra);
                let out46 = _mm256_unpacklo_epi64(lb, rb);
                let out57 = _mm256_unpackhi_epi64(lb, rb);

                v0 = _mm256_castsi256_si128(out02);
                v2 = _mm256_extracti128_si256::<1>(out02);
                v1 = _mm256_castsi256_si128(out13);
                v3 = _mm256_extracti128_si256::<1>(out13);
                v4 = _mm256_castsi256_si128(out46);
                v6 = _mm256_extracti128_si256::<1>(out46);
                v5 = _mm256_castsi256_si128(out57);
                v7 = _mm256_extracti128_si256::<1>(out57);
            }

            let ptr = chunk128.as_mut_ptr();
            let p0 = _mm_loadu_si128(ptr as *const __m128i);
            let p1 = _mm_loadu_si128(ptr.add(16) as *const __m128i);
            let p2 = _mm_loadu_si128(ptr.add(32) as *const __m128i);
            let p3 = _mm_loadu_si128(ptr.add(48) as *const __m128i);
            let p4 = _mm_loadu_si128(ptr.add(64) as *const __m128i);
            let p5 = _mm_loadu_si128(ptr.add(80) as *const __m128i);
            let p6 = _mm_loadu_si128(ptr.add(96) as *const __m128i);
            let p7 = _mm_loadu_si128(ptr.add(112) as *const __m128i);

            _mm_storeu_si128(ptr as *mut __m128i, _mm_xor_si128(p0, v0));
            _mm_storeu_si128(ptr.add(16) as *mut __m128i, _mm_xor_si128(p1, v1));
            _mm_storeu_si128(ptr.add(32) as *mut __m128i, _mm_xor_si128(p2, v2));
            _mm_storeu_si128(ptr.add(48) as *mut __m128i, _mm_xor_si128(p3, v3));
            _mm_storeu_si128(ptr.add(64) as *mut __m128i, _mm_xor_si128(p4, v4));
            _mm_storeu_si128(ptr.add(80) as *mut __m128i, _mm_xor_si128(p5, v5));
            _mm_storeu_si128(ptr.add(96) as *mut __m128i, _mm_xor_si128(p6, v6));
            _mm_storeu_si128(ptr.add(112) as *mut __m128i, _mm_xor_si128(p7, v7));

            b += 8;
        }

        if !rem.is_empty() {
            let mut rk = [zero; ROUNDS + 1];
            for r in 0..=ROUNDS {
                rk[r] = _mm_loadu_si128(self.keys[r].as_ptr() as *const __m128i);
            }

            for block in rem.chunks_mut(16) {
                let ctr_hi = (b as u64) | hi_shifted;
                let t1 = ((base_mid ^ b) as u64) | hi_shifted;
                let tw = [t0, t1, t0 ^ t1 ^ GOLDEN];

                let mut v = _mm_xor_si128(_mm_set_epi64x(ctr_hi as i64, chunk_idx as i64), rk[0]);
                for round in 1..=ROUNDS {
                    let tw_w = tw[round % 3].wrapping_add((round as u64).wrapping_mul(ROUND_SALT));
                    let m = _mm_aesenc_si128(v, zero);
                    let r0 = _mm_srli_si128::<8>(m);
                    let l1 = _mm_add_epi64(m, r0);
                    let r_rot = _mm_or_si128(_mm_slli_epi64::<13>(r0), _mm_srli_epi64::<51>(r0));
                    let r1 = _mm_xor_si128(r_rot, l1);
                    let r2 = _mm_add_epi64(r1, _mm_cvtsi64_si128(tw_w as i64));
                    let l_rot = _mm_or_si128(_mm_slli_epi64::<31>(l1), _mm_srli_epi64::<33>(l1));
                    let l2 = _mm_xor_si128(l_rot, r2);
                    v = _mm_xor_si128(_mm_unpacklo_epi64(l2, r2), rk[round]);
                }

                let mut ks = [0u8; 16];
                _mm_storeu_si128(ks.as_mut_ptr() as *mut __m128i, v);
                for j in 0..block.len() {
                    block[j] ^= ks[j];
                }
                b += 1;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    #[allow(unsafe_code)]
    unsafe fn ctr_chunk_aesni(
        &self,
        stream_nonce: &[u8; 16],
        chunk_idx: u64,
        is_last: bool,
        data: &mut [u8],
    ) {
        use std::arch::x86_64::*;

        let zero = _mm_setzero_si128();
        let golden_v = _mm_set1_epi64x(GOLDEN as i64);

        let base_lo = read_u64(&stream_nonce[0..8]);
        let base_mid = read_u32(&stream_nonce[8..12]);
        let last_mask = if is_last { 0xFFu8 } else { 0x00u8 };
        let hi_top = u32::from_le_bytes([
            stream_nonce[12],
            stream_nonce[13],
            stream_nonce[14],
            stream_nonce[15] ^ last_mask,
        ]) as u64;
        let hi_shifted = hi_top << 32;

        let t0 = base_lo ^ chunk_idx;
        let tw_t0 = _mm_set1_epi64x(t0 as i64);

        let k0 = _mm_loadu_si128(self.keys[0].as_ptr() as *const __m128i);
        let mut kl = [zero; ROUNDS + 1];
        let mut kr = [zero; ROUNDS + 1];
        let mut rs = [zero; ROUNDS];

        for r in 1..=ROUNDS {
            kl[r] = _mm_set1_epi64x(self.keys[r][0] as i64);
            kr[r] = _mm_set1_epi64x(self.keys[r][1] as i64);
            rs[r - 1] = _mm_set1_epi64x((r as u64).wrapping_mul(ROUND_SALT) as i64);
        }

        let main_len = (data.len() / 64) * 64;
        let (main_data, rem) = data.split_at_mut(main_len);
        let mut b = 0u32;

        for chunk64 in main_data.chunks_exact_mut(64) {
            let c0 = (b as u64) | hi_shifted;
            let c1 = ((b + 1) as u64) | hi_shifted;
            let c2 = ((b + 2) as u64) | hi_shifted;
            let c3 = ((b + 3) as u64) | hi_shifted;

            let mut v0 = _mm_xor_si128(_mm_set_epi64x(c0 as i64, chunk_idx as i64), k0);
            let mut v1 = _mm_xor_si128(_mm_set_epi64x(c1 as i64, chunk_idx as i64), k0);
            let mut v2 = _mm_xor_si128(_mm_set_epi64x(c2 as i64, chunk_idx as i64), k0);
            let mut v3 = _mm_xor_si128(_mm_set_epi64x(c3 as i64, chunk_idx as i64), k0);

            let t1_0 = ((base_mid ^ b) as u64) | hi_shifted;
            let t1_1 = ((base_mid ^ (b + 1)) as u64) | hi_shifted;
            let t1_2 = ((base_mid ^ (b + 2)) as u64) | hi_shifted;
            let t1_3 = ((base_mid ^ (b + 3)) as u64) | hi_shifted;

            let tw01_1 = _mm_set_epi64x(t1_1 as i64, t1_0 as i64);
            let tw23_1 = _mm_set_epi64x(t1_3 as i64, t1_2 as i64);
            let tw01_2 = _mm_xor_si128(_mm_xor_si128(tw_t0, tw01_1), golden_v);
            let tw23_2 = _mm_xor_si128(_mm_xor_si128(tw_t0, tw23_1), golden_v);

            let tw01 = [tw_t0, tw01_1, tw01_2];
            let tw23 = [tw_t0, tw23_1, tw23_2];

            for round in 1..=ROUNDS {
                v0 = _mm_aesenc_si128(v0, zero);
                v1 = _mm_aesenc_si128(v1, zero);
                v2 = _mm_aesenc_si128(v2, zero);
                v3 = _mm_aesenc_si128(v3, zero);

                let mut l01 = _mm_unpacklo_epi64(v0, v1);
                let mut r01 = _mm_unpackhi_epi64(v0, v1);
                let mut l23 = _mm_unpacklo_epi64(v2, v3);
                let mut r23 = _mm_unpackhi_epi64(v2, v3);

                let tw_a = _mm_add_epi64(tw01[round % 3], rs[round - 1]);
                let tw_b = _mm_add_epi64(tw23[round % 3], rs[round - 1]);

                l01 = _mm_add_epi64(l01, r01);
                l23 = _mm_add_epi64(l23, r23);

                let rot_r01 = _mm_or_si128(_mm_slli_epi64::<13>(r01), _mm_srli_epi64::<51>(r01));
                let rot_r23 = _mm_or_si128(_mm_slli_epi64::<13>(r23), _mm_srli_epi64::<51>(r23));
                r01 = _mm_xor_si128(rot_r01, l01);
                r23 = _mm_xor_si128(rot_r23, l23);

                r01 = _mm_add_epi64(r01, tw_a);
                r23 = _mm_add_epi64(r23, tw_b);

                let rot_l01 = _mm_or_si128(_mm_slli_epi64::<31>(l01), _mm_srli_epi64::<33>(l01));
                let rot_l23 = _mm_or_si128(_mm_slli_epi64::<31>(l23), _mm_srli_epi64::<33>(l23));
                l01 = _mm_xor_si128(rot_l01, r01);
                l23 = _mm_xor_si128(rot_l23, r23);

                l01 = _mm_xor_si128(l01, kl[round]);
                r01 = _mm_xor_si128(r01, kr[round]);
                l23 = _mm_xor_si128(l23, kl[round]);
                r23 = _mm_xor_si128(r23, kr[round]);

                v0 = _mm_unpacklo_epi64(l01, r01);
                v1 = _mm_unpackhi_epi64(l01, r01);
                v2 = _mm_unpacklo_epi64(l23, r23);
                v3 = _mm_unpackhi_epi64(l23, r23);
            }

            let ptr = chunk64.as_mut_ptr();
            let p0 = _mm_loadu_si128(ptr as *const __m128i);
            let p1 = _mm_loadu_si128(ptr.add(16) as *const __m128i);
            let p2 = _mm_loadu_si128(ptr.add(32) as *const __m128i);
            let p3 = _mm_loadu_si128(ptr.add(48) as *const __m128i);

            _mm_storeu_si128(ptr as *mut __m128i, _mm_xor_si128(p0, v0));
            _mm_storeu_si128(ptr.add(16) as *mut __m128i, _mm_xor_si128(p1, v1));
            _mm_storeu_si128(ptr.add(32) as *mut __m128i, _mm_xor_si128(p2, v2));
            _mm_storeu_si128(ptr.add(48) as *mut __m128i, _mm_xor_si128(p3, v3));

            b += 4;
        }

        if !rem.is_empty() {
            let mut rk = [zero; ROUNDS + 1];
            for r in 0..=ROUNDS {
                rk[r] = _mm_loadu_si128(self.keys[r].as_ptr() as *const __m128i);
            }

            for block in rem.chunks_mut(16) {
                let ctr_hi = (b as u64) | hi_shifted;
                let t1 = ((base_mid ^ b) as u64) | hi_shifted;
                let tw = [t0, t1, t0 ^ t1 ^ GOLDEN];

                let mut v = _mm_xor_si128(_mm_set_epi64x(ctr_hi as i64, chunk_idx as i64), rk[0]);
                for round in 1..=ROUNDS {
                    let tw_w = tw[round % 3].wrapping_add((round as u64).wrapping_mul(ROUND_SALT));
                    let m = _mm_aesenc_si128(v, zero);
                    let r0 = _mm_srli_si128::<8>(m);
                    let l1 = _mm_add_epi64(m, r0);
                    let r_rot = _mm_or_si128(_mm_slli_epi64::<13>(r0), _mm_srli_epi64::<51>(r0));
                    let r1 = _mm_xor_si128(r_rot, l1);
                    let r2 = _mm_add_epi64(r1, _mm_cvtsi64_si128(tw_w as i64));
                    let l_rot = _mm_or_si128(_mm_slli_epi64::<31>(l1), _mm_srli_epi64::<33>(l1));
                    let l2 = _mm_xor_si128(l_rot, r2);
                    v = _mm_xor_si128(_mm_unpacklo_epi64(l2, r2), rk[round]);
                }

                let mut ks = [0u8; 16];
                _mm_storeu_si128(ks.as_mut_ptr() as *mut __m128i, v);
                for j in 0..block.len() {
                    block[j] ^= ks[j];
                }
                b += 1;
            }
        }
    }

    pub fn ctr_chunk_ct(
        &self,
        stream_nonce: &[u8; 16],
        chunk_idx: u64,
        is_last: bool,
        data: &mut [u8],
    ) {
        let base_lo = read_u64(&stream_nonce[0..8]);
        let base_mid = read_u32(&stream_nonce[8..12]);
        let last_mask = if is_last { 0xFFu8 } else { 0x00u8 };

        for (b, block) in data.chunks_mut(16).enumerate() {
            let b_u32 = b as u32;
            let mut ctr = [0u8; 16];
            ctr[0..8].copy_from_slice(&chunk_idx.to_le_bytes());
            ctr[8..12].copy_from_slice(&b_u32.to_le_bytes());
            ctr[12..15].copy_from_slice(&stream_nonce[12..15]);
            ctr[15] = stream_nonce[15] ^ last_mask;

            let mut tweak = *stream_nonce;
            tweak[0..8].copy_from_slice(&(base_lo ^ chunk_idx).to_le_bytes());
            tweak[8..12].copy_from_slice(&(base_mid ^ b_u32).to_le_bytes());
            tweak[15] ^= last_mask;

            let ks = self.encrypt_block_ct(ctr, tweak);
            for j in 0..block.len() {
                block[j] ^= ks[j];
            }
        }
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

fn read_u32(slice: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    u32::from_le_bytes(buf)
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
    fn test_ctr_chunk_8x_matches_scalar() {
        let cipher = Knox256::new(&[0x7Au8; 32]);
        let nonce = [0x3Cu8; 16];

        for is_last in [false, true] {
            let mut fast = vec![0x5Au8; 533];
            let mut slow = fast.clone();
            cipher.ctr_chunk(&nonce, 42, is_last, &mut fast);
            cipher.ctr_chunk_ct(&nonce, 42, is_last, &mut slow);
            assert_eq!(fast, slow);
        }
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
            diff += (c1[i] ^ c2[i]).count_ones() as u32;
        }
        assert!(diff >= 44 && diff <= 84);
    }
}
