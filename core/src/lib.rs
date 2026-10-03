mod argon2_memory;
pub mod bitwarden;
pub mod ffi;
pub mod kdbx;
pub mod password;
mod random;

use std::os::raw::c_char;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// Returns the core version as a static, NUL-terminated string.
/// The pointer is valid for the lifetime of the process and must not be freed.
#[no_mangle]
pub extern "C" fn sailvault_core_version() -> *const c_char {
    VERSION.as_ptr().cast()
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
}
