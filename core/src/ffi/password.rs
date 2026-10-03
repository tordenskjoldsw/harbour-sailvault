use super::{SvString, SV_INVALID_ARGUMENT, SV_OK, SV_RANDOM_UNAVAILABLE};
use super::{SV_CLASS_DIGITS, SV_CLASS_LOWER, SV_CLASS_SYMBOLS, SV_CLASS_UPPER};
use crate::password::{self, CharacterClasses, PasswordError};

/// A random password of `length` characters from the `SV_CLASS_*` classes in
/// `classes`, each class used at least once.
///
/// # Safety
///
/// `out` must be valid for one write. Release the string with
/// `sv_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_generate_password(
    length: usize,
    classes: u32,
    out: *mut SvString,
) -> i32 {
    let Some(out) = out.as_mut() else {
        return SV_INVALID_ARGUMENT;
    };
    *out = SvString::EMPTY;
    let classes = CharacterClasses {
        lower: classes & SV_CLASS_LOWER != 0,
        upper: classes & SV_CLASS_UPPER != 0,
        digits: classes & SV_CLASS_DIGITS != 0,
        symbols: classes & SV_CLASS_SYMBOLS != 0,
    };
    match password::generate(length, classes) {
        Ok(password) => {
            *out = SvString::new(&password);
            SV_OK
        }
        Err(PasswordError::InvalidParameters) => SV_INVALID_ARGUMENT,
        Err(PasswordError::RandomUnavailable) => SV_RANDOM_UNAVAILABLE,
    }
}
