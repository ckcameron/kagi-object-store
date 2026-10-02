// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Optional CPU acceleration libraries with runtime discovery and execution counters.
//!
//! Library handles intentionally remain loaded for the process lifetime after successful
//! symbol resolution. This keeps function pointers valid and lets status/benchmark output
//! distinguish "compiled with support" from "provider actually available and executed".

use std::ffi::CStr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

unsafe fn symbol(library: *mut libc::c_void, name: &CStr) -> Option<*mut libc::c_void> {
    let pointer = libc::dlsym(library, name.as_ptr());
    (!pointer.is_null()).then_some(pointer)
}

fn open(names: &[&CStr]) -> Option<*mut libc::c_void> {
    names.iter().find_map(|name| {
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        (!handle.is_null()).then_some(handle)
    })
}

#[cfg(feature = "isa-l")]
type IsalInit = unsafe extern "C" fn(i32, i32, *const u8, *mut u8);
#[cfg(feature = "isa-l")]
type IsalEncode = unsafe extern "C" fn(i32, i32, i32, *const u8, *const *const u8, *const *mut u8);
#[cfg(feature = "isa-l")]
static ISAL_API: OnceLock<Option<(IsalInit, IsalEncode)>> = OnceLock::new();
#[cfg(feature = "isa-l")]
static ISAL_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "isa-l")]
fn isal_api() -> Option<&'static (IsalInit, IsalEncode)> {
    ISAL_API
        .get_or_init(|| unsafe {
            let library = open(&[c"libisal.so.2", c"libisal.so"])?;
            let result = (|| {
                Some((
                    std::mem::transmute::<*mut libc::c_void, IsalInit>(symbol(
                        library,
                        c"ec_init_tables",
                    )?),
                    std::mem::transmute::<*mut libc::c_void, IsalEncode>(symbol(
                        library,
                        c"ec_encode_data",
                    )?),
                ))
            })();
            if result.is_none() {
                libc::dlclose(library);
            }
            result
        })
        .as_ref()
}

#[cfg(feature = "isa-l")]
pub fn isal_available() -> bool {
    isal_api().is_some()
}

#[cfg(feature = "isa-l")]
pub fn isal_calls() -> u64 {
    ISAL_CALLS.load(Ordering::Relaxed)
}

#[cfg(feature = "isa-l")]
pub fn matrix(
    input: &[u8],
    inputs: usize,
    coeff: &[u8],
    outputs: usize,
    width: usize,
) -> Option<Vec<u8>> {
    let &(init, encode) = isal_api()?;
    if inputs == 0
        || outputs == 0
        || width < 64
        || width > i32::MAX as usize
        || inputs > i32::MAX as usize
        || outputs > i32::MAX as usize
        || input.len() != inputs.checked_mul(width)?
        || coeff.len() != outputs.checked_mul(inputs)?
    {
        return None;
    }

    let mut tables = vec![0; coeff.len().checked_mul(32)?];
    let mut result = vec![0; outputs.checked_mul(width)?];
    let sources: Vec<_> = input.chunks_exact(width).map(|row| row.as_ptr()).collect();
    let destinations: Vec<_> = result
        .chunks_exact_mut(width)
        .map(|row| row.as_mut_ptr())
        .collect();

    // ISA-L accepts arbitrary GF(2^8) coefficient matrices over polynomial 0x11d,
    // matching Kagi's persisted erasure-code field.
    unsafe {
        init(
            inputs as i32,
            outputs as i32,
            coeff.as_ptr(),
            tables.as_mut_ptr(),
        );
        encode(
            width as i32,
            inputs as i32,
            outputs as i32,
            tables.as_ptr(),
            sources.as_ptr(),
            destinations.as_ptr(),
        );
    }
    ISAL_CALLS.fetch_add(1, Ordering::Relaxed);
    Some(result)
}

#[cfg(feature = "ipp")]
type IppXor = unsafe extern "C" fn(*const u8, *mut u8, i32) -> i32;
#[cfg(feature = "ipp")]
static IPP_API: OnceLock<Option<IppXor>> = OnceLock::new();
#[cfg(feature = "ipp")]
static IPP_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "ipp")]
fn ipp_api() -> Option<&'static IppXor> {
    IPP_API
        .get_or_init(|| unsafe {
            let library = open(&[c"libipps.so", c"libipps.so.12", c"libipps.so.11"])?;
            let result = symbol(library, c"ippsXor_8u_I")
                .map(|pointer| std::mem::transmute::<*mut libc::c_void, IppXor>(pointer));
            if result.is_none() {
                libc::dlclose(library);
            }
            result
        })
        .as_ref()
}

#[cfg(feature = "ipp")]
pub fn ipp_available() -> bool {
    ipp_api().is_some()
}

#[cfg(feature = "ipp")]
pub fn ipp_calls() -> u64 {
    IPP_CALLS.load(Ordering::Relaxed)
}

#[cfg(feature = "ipp")]
pub fn xor(dst: &mut [u8], src: &[u8]) -> bool {
    let Some(&xor) = ipp_api() else {
        return false;
    };
    if dst.len() != src.len() || src.is_empty() || src.len() > i32::MAX as usize {
        return false;
    }

    // Execute in scratch space so an unexpected IPP error cannot partially modify
    // the caller's row and then cause the scalar fallback to XOR it a second time.
    let mut candidate = dst.to_vec();
    let status = unsafe { xor(src.as_ptr(), candidate.as_mut_ptr(), src.len() as i32) };
    if status != 0 {
        return false;
    }
    dst.copy_from_slice(&candidate);
    IPP_CALLS.fetch_add(1, Ordering::Relaxed);
    true
}

#[cfg(feature = "aocl")]
type AoclCopy =
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, usize) -> *mut libc::c_void;
#[cfg(feature = "aocl")]
static AOCL_API: OnceLock<Option<AoclCopy>> = OnceLock::new();
#[cfg(feature = "aocl")]
static AOCL_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "aocl")]
fn aocl_api() -> Option<&'static AoclCopy> {
    AOCL_API
        .get_or_init(|| unsafe {
            let library = open(&[c"libaocl-libmem.so", c"libaocl-libmem.so.5"])?;
            let result = symbol(library, c"memcpy")
                .map(|pointer| std::mem::transmute::<*mut libc::c_void, AoclCopy>(pointer));
            if result.is_none() {
                libc::dlclose(library);
            }
            result
        })
        .as_ref()
}

#[cfg(feature = "aocl")]
pub fn aocl_available() -> bool {
    aocl_api().is_some()
}

#[cfg(feature = "aocl")]
pub fn aocl_calls() -> u64 {
    AOCL_CALLS.load(Ordering::Relaxed)
}

#[cfg(feature = "aocl")]
pub fn copy(dst: &mut [u8], src: &[u8]) -> bool {
    let Some(&copy) = aocl_api() else {
        return false;
    };
    if dst.len() != src.len() {
        return false;
    }
    // Rust's distinct shared/mutable slices guarantee memcpy's non-overlap contract.
    let returned = unsafe { copy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
    if returned != dst.as_mut_ptr().cast() {
        return false;
    }
    AOCL_CALLS.fetch_add(1, Ordering::Relaxed);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn missing(name: &str) {
        assert!(
            std::env::var_os("KAGI_REQUIRE_CPU_LIB_TESTS").is_none(),
            "required CPU library {name} is unavailable"
        );
        eprintln!("{name} execution skipped: library unavailable");
    }

    #[cfg(feature = "isa-l")]
    #[test]
    fn isal_matches_independent_field_reference() {
        let width = 4099;
        let input: Vec<u8> = (0..width * 3).map(|i| (i * 13 + 7) as u8).collect();
        let coeff: Vec<u8> = (0..256 * 3).map(|i| i as u8).collect();
        let before = isal_calls();
        let Some(actual) = matrix(&input, 3, &coeff, 256, width) else {
            missing("ISA-L");
            return;
        };
        let mut expected = vec![0u8; 256 * width];
        for row in 0..256 {
            for column in 0..width {
                for source in 0..3 {
                    expected[row * width + column] ^= super::super::gf_mul(
                        coeff[row * 3 + source],
                        input[source * width + column],
                    );
                }
            }
        }
        assert_eq!(actual, expected);
        assert!(isal_available());
        assert!(isal_calls() > before);
    }

    #[cfg(feature = "ipp")]
    #[test]
    fn ipp_xor_matches_reference() {
        let src: Vec<u8> = (0..8197).map(|i| i as u8).collect();
        let mut dst = vec![0x5a; src.len()];
        let before = ipp_calls();
        if !xor(&mut dst, &src) {
            missing("IPP");
            return;
        }
        assert_eq!(dst, src.iter().map(|x| x ^ 0x5a).collect::<Vec<_>>());
        assert!(ipp_available());
        assert!(ipp_calls() > before);
    }

    #[cfg(feature = "aocl")]
    #[test]
    fn aocl_copy_matches_reference() {
        let src: Vec<u8> = (0..1_048_583).map(|i| (i * 31) as u8).collect();
        let mut dst = vec![0; src.len()];
        let before = aocl_calls();
        if !copy(&mut dst, &src) {
            missing("AOCL");
            return;
        }
        assert_eq!(dst, src);
        assert!(aocl_available());
        assert!(aocl_calls() > before);
    }
}
