//! C API for the C++ bridge, declared in `include/sailvault_core.h`.
//!
//! The database stays in Rust behind an opaque handle. Lists carry ids,
//! titles, user names and group names; field values cross the boundary one
//! at a time, when the user shows or copies them. Every string handed out is
//! zeroized by `sv_string_free`.

mod bitwarden;
mod database;
mod edit;
mod password;
mod read;
#[cfg(test)]
mod tests;

use std::slice;

use zeroize::Zeroizing;

use crate::bitwarden::ImportError;
use crate::kdbx::{Database, KdbxError, NewGroup, Result};

pub const SV_OK: i32 = 0;
pub const SV_INVALID_ARGUMENT: i32 = 1;
pub const SV_NOT_KDBX: i32 = 2;
pub const SV_UNSUPPORTED_FORMAT: i32 = 4;
pub const SV_INVALID_CREDENTIALS: i32 = 5;
pub const SV_INVALID_KEY_FILE: i32 = 6;
pub const SV_CORRUPTED: i32 = 7;
pub const SV_LIMIT_EXCEEDED: i32 = 8;
pub const SV_NOT_FOUND: i32 = 9;
pub const SV_WRITE_FAILED: i32 = 10;
pub const SV_RANDOM_UNAVAILABLE: i32 = 11;
pub const SV_NOT_AN_EXPORT: i32 = 12;

pub const SV_EXPORT_UNENCRYPTED: i32 = 0;
pub const SV_EXPORT_PASSWORD_PROTECTED: i32 = 1;
pub const SV_EXPORT_ACCOUNT_RESTRICTED: i32 = 2;

pub const SV_KDF_STANDARD: u32 = 0;
pub const SV_KDF_HIGH: u32 = 1;
pub const SV_KDF_MAXIMUM: u32 = 2;

pub const SV_CLASS_LOWER: u32 = 1;
pub const SV_CLASS_UPPER: u32 = 2;
pub const SV_CLASS_DIGITS: u32 = 4;
pub const SV_CLASS_SYMBOLS: u32 = 8;

pub const SV_COLUMN_TITLE: u32 = 0;
pub const SV_COLUMN_USER_NAME: u32 = 1;
pub const SV_COLUMN_GROUP: u32 = 2;

pub const SV_CURRENT_VERSION: i64 = -1;

pub const SV_UUID_LENGTH: usize = 16;
const UUID_LENGTH: usize = SV_UUID_LENGTH;

pub struct SvDatabase {
    database: Database,
}

// The C++ bridge opens and saves the database and reads imports on a pool
// thread and uses them on the main thread, so the handles must stay Send
// and Sync.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SvDatabase>();
    assert_send_sync::<SvImport>();
};

/// A Bitwarden export, read and mapped, ready to be added to a database.
pub struct SvImport {
    group: NewGroup,
}

#[repr(C)]
pub struct SvString {
    pub data: *mut u8,
    pub length: usize,
}

impl SvString {
    const EMPTY: Self = Self {
        data: std::ptr::null_mut(),
        length: 0,
    };

    fn new(text: &str) -> Self {
        let boxed: Box<[u8]> = text.as_bytes().into();
        let length = boxed.len();
        Self {
            data: Box::into_raw(boxed).cast(),
            length,
        }
    }
}

/// A serialized database file.
#[repr(C)]
pub struct SvBytes {
    pub data: *mut u8,
    pub length: usize,
}

impl SvBytes {
    const EMPTY: Self = Self {
        data: std::ptr::null_mut(),
        length: 0,
    };

    fn new(bytes: Vec<u8>) -> Self {
        let boxed = bytes.into_boxed_slice();
        let length = boxed.len();
        Self {
            data: Box::into_raw(boxed).cast(),
            length,
        }
    }
}

/// A field of a new entry: UTF-8 key and value, not NUL-terminated.
#[repr(C)]
pub struct SvField {
    pub key: *const u8,
    pub key_length: usize,
    pub value: *const u8,
    pub value_length: usize,
}

/// One row of an entry or group list. All strings are owned by the list.
struct ListItem {
    uuid: [u8; UUID_LENGTH],
    is_group: bool,
    title: Zeroizing<String>,
    user_name: Zeroizing<String>,
    group: Zeroizing<String>,
}

pub struct SvList {
    items: Vec<ListItem>,
}

struct FieldInfo {
    key: Zeroizing<String>,
    protected: bool,
}

pub struct SvFieldList {
    fields: Vec<FieldInfo>,
}

fn status(error: KdbxError) -> i32 {
    match error {
        KdbxError::NotKdbx => SV_NOT_KDBX,
        KdbxError::UnsupportedVersion { .. }
        | KdbxError::UnsupportedCipher
        | KdbxError::UnsupportedCompression
        | KdbxError::UnsupportedKdf => SV_UNSUPPORTED_FORMAT,
        KdbxError::InvalidCredentials => SV_INVALID_CREDENTIALS,
        KdbxError::InvalidKeyFile => SV_INVALID_KEY_FILE,
        KdbxError::KdfParametersOutOfRange | KdbxError::LimitExceeded(_) => SV_LIMIT_EXCEEDED,
        KdbxError::InvalidHeader(_)
        | KdbxError::HeaderCorrupted
        | KdbxError::PayloadCorrupted
        | KdbxError::DecryptionFailed
        | KdbxError::DecompressionFailed
        | KdbxError::InvalidInnerHeader(_)
        | KdbxError::InvalidXml(_) => SV_CORRUPTED,
        KdbxError::CompressionFailed
        | KdbxError::EncryptionFailed
        | KdbxError::WriteVerificationFailed => SV_WRITE_FAILED,
        KdbxError::RandomUnavailable => SV_RANDOM_UNAVAILABLE,
        KdbxError::InvalidEntry(_)
        | KdbxError::InvalidGroup(_)
        | KdbxError::RootGroupProtected
        | KdbxError::NotInRecycleBin => SV_INVALID_ARGUMENT,
        KdbxError::UnknownGroup | KdbxError::UnknownEntry => SV_NOT_FOUND,
    }
}

fn import_status(error: ImportError) -> i32 {
    match error {
        ImportError::NotAnExport => SV_NOT_AN_EXPORT,
        ImportError::WrongPassword => SV_INVALID_CREDENTIALS,
        ImportError::PasswordRequired => SV_INVALID_ARGUMENT,
        ImportError::AccountRestricted | ImportError::UnsupportedEncStringType(_) => {
            SV_UNSUPPORTED_FORMAT
        }
        ImportError::InvalidKdfParameters | ImportError::TooLarge | ImportError::FolderTooDeep => {
            SV_LIMIT_EXCEEDED
        }
        ImportError::InvalidEncString
        | ImportError::MacMismatch
        | ImportError::DecryptionFailed
        | ImportError::InvalidUtf8
        | ImportError::InvalidJson => SV_CORRUPTED,
    }
}

/// Writes the value of `result` to `out` and returns the status; `out` is
/// reset to its default on an error.
fn deliver<T: Default>(result: Result<T>, out: &mut T) -> i32 {
    match result {
        Ok(value) => {
            *out = value;
            SV_OK
        }
        Err(error) => {
            *out = T::default();
            status(error)
        }
    }
}

/// # Safety
///
/// `data` must be null or valid for reads of `length` bytes.
unsafe fn bytes<'a>(data: *const u8, length: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        (length == 0).then_some(&[][..])
    } else {
        Some(slice::from_raw_parts(data, length))
    }
}

/// # Safety
///
/// As for `bytes`; the bytes must also be UTF-8.
unsafe fn utf8<'a>(data: *const u8, length: usize) -> Option<&'a str> {
    bytes(data, length).and_then(|bytes| std::str::from_utf8(bytes).ok())
}

/// # Safety
///
/// `uuid` must be null or valid for reads of 16 bytes.
unsafe fn read_uuid(uuid: *const u8) -> Option<[u8; UUID_LENGTH]> {
    if uuid.is_null() {
        return None;
    }
    let mut copy = [0u8; UUID_LENGTH];
    copy.copy_from_slice(slice::from_raw_parts(uuid, UUID_LENGTH));
    Some(copy)
}

/// # Safety
///
/// `out` must be valid for writes of 16 bytes.
unsafe fn write_uuid(out: *mut u8, uuid: &[u8; UUID_LENGTH]) {
    slice::from_raw_parts_mut(out, UUID_LENGTH).copy_from_slice(uuid);
}

/// # Safety
///
/// `fields` must be null or valid for reads of `field_count` entries whose
/// key and value pointers follow the rules of `bytes`.
unsafe fn field_pairs<'a>(
    fields: *const SvField,
    field_count: usize,
) -> Option<Vec<(&'a str, &'a str)>> {
    if fields.is_null() {
        return (field_count == 0).then(Vec::new);
    }
    slice::from_raw_parts(fields, field_count)
        .iter()
        .map(|field| {
            Some((
                utf8(field.key, field.key_length)?,
                utf8(field.value, field.value_length)?,
            ))
        })
        .collect()
}

/// Releases a file from `sv_database_save` or `sv_database_create`.
///
/// # Safety
///
/// `bytes` must come from this API and not have been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_bytes_free(bytes: SvBytes) {
    if !bytes.data.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            bytes.data,
            bytes.length,
        )));
    }
}

/// Zeroizes and releases a string from this API.
///
/// # Safety
///
/// `string` must come from this API and not have been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_string_free(string: SvString) {
    if !string.data.is_null() {
        let boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            string.data,
            string.length,
        ));
        drop(Zeroizing::new(boxed));
    }
}
