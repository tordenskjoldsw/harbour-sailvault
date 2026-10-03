use super::{bytes, status, utf8, SvBytes, SvDatabase, SV_INVALID_ARGUMENT, SV_OK};
use super::{SV_KDF_HIGH, SV_KDF_MAXIMUM, SV_KDF_STANDARD};
use crate::kdbx::{CompositeKey, Database, KdfLevel};

/// Opens a KDBX 4 database. At least one of password and key file must be
/// given. Runs the KDF: call it off the UI thread.
///
/// # Safety
///
/// Each pointer must be null or valid for reads of its length; `out` must be
/// valid for one write. On success `*out` receives a handle that must be
/// released with `sv_database_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_open(
    data: *const u8,
    data_length: usize,
    password: *const u8,
    password_length: usize,
    has_password: bool,
    key_file: *const u8,
    key_file_length: usize,
    out: *mut *mut SvDatabase,
) -> i32 {
    let Some(out) = out.as_mut() else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let (Some(data), Some(password), Some(key_file)) = (
        bytes(data, data_length),
        bytes(password, password_length),
        bytes(key_file, key_file_length),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    let key = match CompositeKey::new(
        has_password.then_some(password),
        (!key_file.is_empty()).then_some(key_file),
    ) {
        Ok(key) => key,
        Err(error) => return status(error),
    };
    match Database::open(data, key) {
        Ok(database) => {
            *out = Box::into_raw(Box::new(SvDatabase { database }));
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Creates a new, empty database named `name`, protected by `password` with
/// the key derivation `SV_KDF_*` `kdf_level` (see `Database::create`), and
/// serializes it as the file to write. Runs the
/// KDF: call it off the UI thread. On success `*out` receives the unlocked
/// handle and `*file_out` the file; release them with `sv_database_free` and
/// `sv_bytes_free`.
///
/// # Safety
///
/// `password` and `name` must be valid UTF-8 of their lengths; `out` and
/// `file_out` valid for one write each.
#[no_mangle]
pub unsafe extern "C" fn sv_database_create(
    password: *const u8,
    password_length: usize,
    name: *const u8,
    name_length: usize,
    kdf_level: u32,
    now: i64,
    out: *mut *mut SvDatabase,
    file_out: *mut SvBytes,
) -> i32 {
    let (Some(out), Some(file_out)) = (out.as_mut(), file_out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    *file_out = SvBytes::EMPTY;
    let (Some(password), Some(name)) = (
        bytes(password, password_length).filter(|password| !password.is_empty()),
        utf8(name, name_length),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    let level = match kdf_level {
        SV_KDF_STANDARD => KdfLevel::Standard,
        SV_KDF_HIGH => KdfLevel::High,
        SV_KDF_MAXIMUM => KdfLevel::Maximum,
        _ => return SV_INVALID_ARGUMENT,
    };
    let created = CompositeKey::new(Some(password), None)
        .and_then(|key| Database::create(key, name, level, now))
        .and_then(|database| Ok((database.save()?, database)));
    match created {
        Ok((file, database)) => {
            *file_out = SvBytes::new(file);
            *out = Box::into_raw(Box::new(SvDatabase { database }));
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Locks the database: drops and zeroizes all decrypted data.
///
/// # Safety
///
/// `database` must be null or a handle from `sv_database_open` or
/// `sv_database_create` that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_database_free(database: *mut SvDatabase) {
    if !database.is_null() {
        drop(Box::from_raw(database));
    }
}

/// Serializes the database as a KDBX 4 file with fresh seeds, verified by
/// decrypting it again. Runs the KDF: call it off the UI thread. Release the
/// result with `sv_bytes_free`.
///
/// # Safety
///
/// `database` must be a live handle that no other thread modifies or frees
/// meanwhile; `out` must be valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_save(database: *const SvDatabase, out: *mut SvBytes) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = SvBytes::EMPTY;
    match database.database.save() {
        Ok(file) => {
            *out = SvBytes::new(file);
            SV_OK
        }
        Err(error) => status(error),
    }
}
