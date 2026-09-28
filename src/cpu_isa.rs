// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Runtime-dispatched x86-64 GF(256) operations. The field polynomial is 0x11d.
//! Specialized instructions are confined to target-feature functions, keeping the
//! portable binary safe on older Intel and AMD processors.

pub(super) fn multiply_add(dst: &mut [u8], src: &[u8], coefficient: u8) {
    assert_eq!(dst.len(), src.len());
    #[cfg(target_arch = "x86_64")]
    if src.len() >= 64
        && std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512bw")
    {
        // SAFETY: both the CPU and OS register-state support are checked above.
        unsafe { avx512_multiply_add(dst, src, coefficient) };
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if src.len() >= 32 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: runtime detection guards AVX2; equal slice lengths are checked.
        unsafe { avx2_multiply_add(dst, src, coefficient) };
        return;
    }
    scalar(dst, src, coefficient);
}

fn scalar(dst: &mut [u8], src: &[u8], coefficient: u8) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= super::gf_mul(coefficient, *s);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_multiply_add(dst: &mut [u8], src: &[u8], coefficient: u8) {
    use std::arch::x86_64::*;
    let mut low = [0u8; 16];
    let mut high = [0u8; 16];
    for i in 0..16 {
        low[i] = super::gf_mul(coefficient, i as u8);
        high[i] = super::gf_mul(coefficient, (i as u8) << 4);
    }
    // Each 128-bit shuffle lane receives its own complete nibble table.
    let low = _mm256_broadcastsi128_si256(_mm_loadu_si128(low.as_ptr().cast()));
    let high = _mm256_broadcastsi128_si256(_mm_loadu_si128(high.as_ptr().cast()));
    let mask = _mm256_set1_epi8(15);
    let end = src.len() / 32 * 32;
    for offset in (0..end).step_by(32) {
        let input = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
        let lo = _mm256_and_si256(input, mask);
        let hi = _mm256_and_si256(_mm256_srli_epi16(input, 4), mask);
        let product = _mm256_xor_si256(_mm256_shuffle_epi8(low, lo), _mm256_shuffle_epi8(high, hi));
        let previous = _mm256_loadu_si256(dst.as_ptr().add(offset).cast());
        _mm256_storeu_si256(
            dst.as_mut_ptr().add(offset).cast(),
            _mm256_xor_si256(previous, product),
        );
    }
    scalar(&mut dst[end..], &src[end..], coefficient);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn avx512_multiply_add(dst: &mut [u8], src: &[u8], coefficient: u8) {
    use std::arch::x86_64::*;
    let mut low = [0u8; 16];
    let mut high = [0u8; 16];
    for i in 0..16 {
        low[i] = super::gf_mul(coefficient, i as u8);
        high[i] = super::gf_mul(coefficient, (i as u8) << 4);
    }
    // Each 128-bit shuffle lane receives its own complete nibble table.
    let low = _mm512_broadcast_i32x4(_mm_loadu_si128(low.as_ptr().cast()));
    let high = _mm512_broadcast_i32x4(_mm_loadu_si128(high.as_ptr().cast()));
    let mask = _mm512_set1_epi8(15);
    let end = src.len() / 64 * 64;
    for offset in (0..end).step_by(64) {
        let input = _mm512_loadu_si512(src.as_ptr().add(offset).cast());
        let lo = _mm512_and_si512(input, mask);
        let hi = _mm512_and_si512(_mm512_srli_epi16(input, 4), mask);
        let product = _mm512_xor_si512(_mm512_shuffle_epi8(low, lo), _mm512_shuffle_epi8(high, hi));
        let previous = _mm512_loadu_si512(dst.as_ptr().add(offset).cast());
        _mm512_storeu_si512(
            dst.as_mut_ptr().add(offset).cast(),
            _mm512_xor_si512(previous, product),
        );
    }
    scalar(&mut dst[end..], &src[end..], coefficient);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    fn check_vector(kernel: unsafe fn(&mut [u8], &[u8], u8)) {
        for coefficient in 0..=255 {
            let input: Vec<u8> = (0..259).map(|i| i as u8).collect();
            let mut actual = vec![0xabu8; input.len()];
            let mut expected = actual.clone();
            scalar(&mut expected[1..], &input[1..], coefficient);
            unsafe {
                kernel(&mut actual[1..], &input[1..], coefficient);
            }
            assert_eq!(actual, expected);
        }
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_all_coefficients_match_reference() {
        if std::is_x86_feature_detected!("avx2") {
            check_vector(avx2_multiply_add);
        } else {
            eprintln!("AVX2 execution unavailable");
        }
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_all_coefficients_match_reference() {
        if std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512bw") {
            check_vector(avx512_multiply_add);
        } else {
            eprintln!("AVX-512 execution unavailable");
        }
    }
    #[test]
    fn dispatched_field_arithmetic_matches_all_byte_pairs() {
        for coefficient in 0..=255 {
            // Unaligned slices and a tail exercise SIMD boundary handling.
            let input: Vec<u8> = (0..259).map(|i| i as u8).collect();
            let mut actual = vec![0xabu8; input.len()];
            let mut expected = actual.clone();
            scalar(&mut expected[1..], &input[1..], coefficient);
            multiply_add(&mut actual[1..], &input[1..], coefficient);
            assert_eq!(actual, expected, "coefficient {coefficient}");
        }
        for length in 0..65 {
            let src = vec![0xff; length];
            let mut actual = vec![0x42; length];
            let mut expected = actual.clone();
            scalar(&mut expected, &src, 193);
            multiply_add(&mut actual, &src, 193);
            assert_eq!(actual, expected);
        }
    }
}
