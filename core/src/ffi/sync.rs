use zeroize::Zeroizing;

use super::{
    status, utf8, write_uuid, SvDatabase, SvString, SV_INVALID_ARGUMENT, SV_NOT_FOUND, SV_OK,
};
use super::{
    SV_SYNC_APP_PASSWORD, SV_SYNC_CERTIFICATE, SV_SYNC_PATH, SV_SYNC_SERVER, SV_SYNC_USER,
};
use crate::kdbx::SyncSettings;

/// One `SV_SYNC_*` setting from the database's sync entry, or
/// `SV_NOT_FOUND` without one. Release the result with `sv_string_free`.
///
/// # Safety
///
/// `database` must be a live handle; `out` must be valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_sync_setting(
    database: *const SvDatabase,
    setting: u32,
    out: *mut SvString,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = SvString::EMPTY;
    let Some(settings) = database.database.sync_settings() else {
        return SV_NOT_FOUND;
    };
    let value = match setting {
        SV_SYNC_SERVER => &settings.server,
        SV_SYNC_USER => &settings.user,
        SV_SYNC_APP_PASSWORD => &settings.app_password,
        SV_SYNC_PATH => &settings.path,
        SV_SYNC_CERTIFICATE => &settings.certificate,
        _ => return SV_INVALID_ARGUMENT,
    };
    *out = SvString::new(value);
    SV_OK
}

/// Stores the sync settings, UTF-8 each, in the database's sync entry,
/// created in the root group when there is none, and writes its UUID to
/// `uuid_out`. The change is in memory until the next save.
///
/// # Safety
///
/// Each string pointer must be valid for reads of its length; `database`
/// must be a live handle no other thread uses; `uuid_out` must be valid for
/// 16 bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sv_database_set_sync_settings(
    database: *mut SvDatabase,
    server: *const u8,
    server_length: usize,
    user: *const u8,
    user_length: usize,
    app_password: *const u8,
    app_password_length: usize,
    path: *const u8,
    path_length: usize,
    certificate: *const u8,
    certificate_length: usize,
    now: i64,
    uuid_out: *mut u8,
) -> i32 {
    let (Some(database), false) = (database.as_mut(), uuid_out.is_null()) else {
        return SV_INVALID_ARGUMENT;
    };
    let text = |data, length| utf8(data, length).map(|text| Zeroizing::new(text.to_owned()));
    let (Some(server), Some(user), Some(app_password), Some(path), Some(certificate)) = (
        text(server, server_length),
        text(user, user_length),
        text(app_password, app_password_length),
        text(path, path_length),
        text(certificate, certificate_length),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    let settings = SyncSettings {
        server,
        user,
        app_password,
        path,
        certificate,
    };
    match database.database.set_sync_settings(&settings, now) {
        Ok(uuid) => {
            write_uuid(uuid_out, &uuid);
            SV_OK
        }
        Err(error) => status(error),
    }
}
