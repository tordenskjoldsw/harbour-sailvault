use super::{bytes, status, utf8, SvBytes, SvDatabase, SvMergeChanges, SV_INVALID_ARGUMENT, SV_OK};
use super::{SV_KDF_HIGH, SV_KDF_MAXIMUM, SV_KDF_STANDARD};
use crate::kdbx::{self, CompositeKey, Database, KdfLevel};

fn level(kdf_level: u32) -> Option<KdfLevel> {
    match kdf_level {
        SV_KDF_STANDARD => Some(KdfLevel::Standard),
        SV_KDF_HIGH => Some(KdfLevel::High),
        SV_KDF_MAXIMUM => Some(KdfLevel::Maximum),
        _ => None,
    }
}

/// Reads the format version from the first twelve bytes of a KDBX file,
/// without credentials: major 3 is a KDBX 3 file that opens as KDBX 4.
///
/// # Safety
///
/// `data` must be null or valid for reads of `data_length` bytes; `major`
/// and `minor` must be valid for one write each.
#[no_mangle]
pub unsafe extern "C" fn sv_kdbx_version(
    data: *const u8,
    data_length: usize,
    major: *mut u16,
    minor: *mut u16,
) -> i32 {
    let (Some(data), Some(major), Some(minor)) =
        (bytes(data, data_length), major.as_mut(), minor.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    match kdbx::version(data) {
        Ok((file_major, file_minor)) => {
            *major = file_major;
            *minor = file_minor;
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Opens a KDBX 4 database, or a KDBX 3 database as KDBX 4. At least one of password and key file must be
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
/// serializes it as the file to write. Runs the KDF: call it off the UI
/// thread. On success `*out` receives the unlocked handle and `*file_out`
/// the file; release them with `sv_database_free` and `sv_bytes_free`.
///
/// # Safety
///
/// `password` must be valid for reads of `password_length` bytes and `name`
/// be UTF-8 of `name_length` bytes; `out` and `file_out` valid for one write
/// each.
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
    let Some(level) = level(kdf_level) else {
        return SV_INVALID_ARGUMENT;
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

/// Sets `*from_kdbx3` to whether the database was read from a KDBX 3 file.
///
/// # Safety
///
/// `database` must be a live handle; `from_kdbx3` must be valid for one
/// write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_from_kdbx3(
    database: *const SvDatabase,
    from_kdbx3: *mut bool,
) -> i32 {
    let (Some(database), Some(from_kdbx3)) = (database.as_ref(), from_kdbx3.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *from_kdbx3 = database.database.from_kdbx3();
    SV_OK
}

/// Switches the key derivation to Argon2id at the `SV_KDF_*` `kdf_level`
/// from the next save on.
///
/// # Safety
///
/// `database` must be a live handle that no other thread uses meanwhile.
#[no_mangle]
pub unsafe extern "C" fn sv_database_set_kdf_level(
    database: *mut SvDatabase,
    kdf_level: u32,
) -> i32 {
    let (Some(database), Some(level)) = (database.as_mut(), level(kdf_level)) else {
        return SV_INVALID_ARGUMENT;
    };
    database.database.set_kdf_level(level);
    SV_OK
}

/// Opens another copy of `like`, such as the file on the computer, with the
/// credentials `like` was unlocked with; they never leave the core. Runs the
/// KDF: call it off the UI thread. On success `*out` receives a handle to
/// release with `sv_database_free`.
///
/// # Safety
///
/// `like` must be a live handle that no other thread modifies meanwhile;
/// `data` must be valid for reads of `data_length` bytes and `out` for one
/// write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_open_like(
    like: *const SvDatabase,
    data: *const u8,
    data_length: usize,
    out: *mut *mut SvDatabase,
) -> i32 {
    let Some(out) = out.as_mut() else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let (Some(like), Some(data)) = (like.as_ref(), bytes(data, data_length)) else {
        return SV_INVALID_ARGUMENT;
    };
    match like.database.open_like(data) {
        Ok(database) => {
            *out = Box::into_raw(Box::new(SvDatabase { database }));
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Merges `source`, another copy of the database, into `database` (see
/// `Database::merge_from`) and reports what changed in `*out`. Nothing
/// changes on an error.
///
/// # Safety
///
/// `database` and `source` must be distinct live handles that no other
/// thread uses meanwhile; `out` must be valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_merge(
    database: *mut SvDatabase,
    source: *const SvDatabase,
    out: *mut SvMergeChanges,
) -> i32 {
    if std::ptr::eq(database, source) {
        return SV_INVALID_ARGUMENT;
    }
    let (Some(database), Some(source), Some(out)) =
        (database.as_mut(), source.as_ref(), out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    match database.database.merge_from(&source.database) {
        Ok(changes) => {
            *out = SvMergeChanges {
                added: changes.added,
                modified: changes.modified,
                moved: changes.moved,
                deleted: changes.deleted,
                metadata: changes.metadata,
            };
            SV_OK
        }
        Err(error) => status(error),
    }
}
