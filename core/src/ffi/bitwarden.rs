use super::{bytes, import_status, status, utf8, SvDatabase, SvImport, SV_INVALID_ARGUMENT, SV_OK};
use super::{SV_EXPORT_ACCOUNT_RESTRICTED, SV_EXPORT_PASSWORD_PROTECTED, SV_EXPORT_UNENCRYPTED};
use crate::bitwarden::{self, ExportKind};

/// The kind of a Bitwarden export (`SV_EXPORT_*`), from its top level only,
/// so the UI can ask for a password or warn about a plain file.
///
/// # Safety
///
/// `data` must be valid for reads of `length` bytes and `kind_out` for one
/// write.
#[no_mangle]
pub unsafe extern "C" fn sv_bitwarden_export_kind(
    data: *const u8,
    length: usize,
    kind_out: *mut i32,
) -> i32 {
    let (Some(data), Some(kind_out)) = (bytes(data, length), kind_out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    match bitwarden::export_kind(data) {
        Ok(kind) => {
            *kind_out = match kind {
                ExportKind::Unencrypted => SV_EXPORT_UNENCRYPTED,
                ExportKind::PasswordProtected => SV_EXPORT_PASSWORD_PROTECTED,
                ExportKind::AccountRestricted => SV_EXPORT_ACCOUNT_RESTRICTED,
            };
            SV_OK
        }
        Err(error) => import_status(error),
    }
}

/// Reads a Bitwarden export and maps it to a group named `group_name`. A
/// password-protected export needs `password` and runs its KDF: call this
/// off the UI thread. Release the result with `sv_import_free`.
///
/// # Safety
///
/// Each pointer must be null or valid for reads of its length; `group_name`
/// must be UTF-8; `out` must be valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_bitwarden_read(
    data: *const u8,
    length: usize,
    password: *const u8,
    password_length: usize,
    has_password: bool,
    group_name: *const u8,
    group_name_length: usize,
    out: *mut *mut SvImport,
) -> i32 {
    let Some(out) = out.as_mut() else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let (Some(data), Some(password), Some(group_name)) = (
        bytes(data, length),
        bytes(password, password_length),
        utf8(group_name, group_name_length),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    let group = bitwarden::read_export(data, has_password.then_some(password))
        .and_then(|vault| bitwarden::import_group(&vault, group_name));
    match group {
        Ok(group) => {
            *out = Box::into_raw(Box::new(SvImport { group }));
            SV_OK
        }
        Err(error) => import_status(error),
    }
}

/// Merges an import into the root group's group of the same name, created
/// when missing, in one step (see `Database::merge_group_tree`), and writes
/// how many entries were added and updated. In memory only until
/// `sv_database_save`.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread; `import`
/// a live handle from `sv_bitwarden_read`; `added_out` and `updated_out`
/// valid for one write each.
#[no_mangle]
pub unsafe extern "C" fn sv_database_import(
    database: *mut SvDatabase,
    import: *const SvImport,
    now: i64,
    added_out: *mut usize,
    updated_out: *mut usize,
) -> i32 {
    let (Some(database), Some(import), Some(added_out), Some(updated_out)) = (
        database.as_mut(),
        import.as_ref(),
        added_out.as_mut(),
        updated_out.as_mut(),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    *added_out = 0;
    *updated_out = 0;
    match database.database.merge_group_tree(&import.group, now) {
        Ok(summary) => {
            *added_out = summary.added;
            *updated_out = summary.updated;
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Releases an import; every value in it is zeroized.
///
/// # Safety
///
/// `import` must be null or a handle from `sv_bitwarden_read` that has not
/// been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_import_free(import: *mut SvImport) {
    if !import.is_null() {
        drop(Box::from_raw(import));
    }
}
