//! Optional CPU libraries. Their public entry points perform their own ISA dispatch.
//! Library handles intentionally live for the process lifetime with their symbols.
use std::ffi::CStr;
use std::sync::OnceLock;

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
pub fn matrix(
    input: &[u8],
    inputs: usize,
    coeff: &[u8],
    outputs: usize,
    width: usize,
) -> Option<Vec<u8>> {
    type Init = unsafe extern "C" fn(i32, i32, *const u8, *mut u8);
    type Encode = unsafe extern "C" fn(i32, i32, i32, *const u8, *const *const u8, *const *mut u8);
    static API: OnceLock<Option<(Init, Encode)>> = OnceLock::new();
    let &(init, encode) = API
        .get_or_init(|| unsafe {
            let library = open(&[c"libisal.so.2", c"libisal.so"])?;
            let result = (|| {
                Some((
                    std::mem::transmute::<*mut libc::c_void, Init>(symbol(
                        library,
                        c"ec_init_tables",
                    )?),
                    std::mem::transmute::<*mut libc::c_void, Encode>(symbol(
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
        .as_ref()?;
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
    // ISA-L documents arbitrary coefficient matrices over the same 0x11d field.
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
    Some(result)
}
#[cfg(feature = "ipp")]
pub fn xor(dst: &mut [u8], src: &[u8]) -> bool {
    type Xor = unsafe extern "C" fn(*const u8, *mut u8, i32) -> i32;
    static API: OnceLock<Option<Xor>> = OnceLock::new();
    let Some(&xor) = API
        .get_or_init(|| unsafe {
            let library = open(&[c"libipps.so", c"libipps.so.11"])?;
            let result = symbol(library, c"ippsXor_8u_I")
                .map(|p| std::mem::transmute::<*mut libc::c_void, Xor>(p));
            if result.is_none() {
                libc::dlclose(library);
            }
            result
        })
        .as_ref()
    else {
        return false;
    };
    if dst.len() != src.len() || src.is_empty() || src.len() > i32::MAX as usize {
        return false;
    }
    // Valid nonoverlapping buffers and positive length avoid IPP argument errors.
    let status = unsafe { xor(src.as_ptr(), dst.as_mut_ptr(), src.len() as i32) };
    assert_eq!(
        status, 0,
        "IPP XOR failed; refusing to repeat a possibly modified operation"
    );
    true
}

#[cfg(feature = "aocl")]
pub fn copy(dst: &mut [u8], src: &[u8]) -> bool {
    type Copy =
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, usize) -> *mut libc::c_void;
    static API: OnceLock<Option<Copy>> = OnceLock::new();
    let Some(&copy) = API
        .get_or_init(|| unsafe {
            let library = open(&[c"libaocl-libmem.so"])?;
            let result = symbol(library, c"memcpy")
                .map(|p| std::mem::transmute::<*mut libc::c_void, Copy>(p));
            if result.is_none() {
                libc::dlclose(library);
            }
            result
        })
        .as_ref()
    else {
        return false;
    };
    if dst.len() != src.len() {
        return false;
    }
    // Rust's distinct shared/mutable slices guarantee memcpy's non-overlap contract.
    unsafe {
        copy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len());
    }
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
    }
    #[cfg(feature = "ipp")]
    #[test]
    fn ipp_xor_matches_reference() {
        let src: Vec<u8> = (0..8197).map(|i| i as u8).collect();
        let mut dst = vec![0x5a; src.len()];
        if !xor(&mut dst, &src) {
            missing("IPP");
            return;
        }
        assert_eq!(dst, src.iter().map(|x| x ^ 0x5a).collect::<Vec<_>>());
    }
    #[cfg(feature = "aocl")]
    #[test]
    fn aocl_copy_matches_reference() {
        let src: Vec<u8> = (0..1_048_583).map(|i| (i * 31) as u8).collect();
        let mut dst = vec![0; src.len()];
        if !copy(&mut dst, &src) {
            missing("AOCL");
            return;
        }
        assert_eq!(dst, src);
    }
}
