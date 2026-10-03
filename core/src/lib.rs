use std::os::raw::c_char;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// Returns the core version as a static, NUL-terminated string.
/// The pointer is valid for the lifetime of the process and must not be freed.
#[no_mangle]
pub extern "C" fn sailvault_core_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

fn fill_random(buffer: &mut [u8]) -> bool {
    getrandom::getrandom(buffer).is_ok()
}

/// Fills `buffer` with `length` bytes from the operating system's CSPRNG.
/// Returns false if `buffer` is null or the CSPRNG is unavailable.
///
/// # Safety
///
/// `buffer` must be null or valid for writes of `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn sailvault_fill_random(buffer: *mut u8, length: usize) -> bool {
    if buffer.is_null() {
        return length == 0;
    }
    fill_random(std::slice::from_raw_parts_mut(buffer, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_is_nul_terminated_package_version() {
        let version = CStr::from_bytes_with_nul(VERSION.as_bytes()).unwrap();
        assert_eq!(version.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn fill_random_produces_distinct_keys() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        assert!(fill_random(&mut first));
        assert!(fill_random(&mut second));
        assert_ne!(first, second);
    }

    #[test]
    fn fill_random_rejects_null_buffer() {
        assert!(!unsafe { sailvault_fill_random(std::ptr::null_mut(), 32) });
        assert!(unsafe { sailvault_fill_random(std::ptr::null_mut(), 0) });
    }
}
