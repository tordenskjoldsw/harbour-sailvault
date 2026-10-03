//! C API for the C++ bridge, declared in `include/sailvault_core.h`.
//!
//! The database stays in Rust behind an opaque handle. Lists carry ids,
//! titles, user names and group names; field values cross the boundary one
//! at a time, when the user shows or copies them. Every string handed out is
//! zeroized by `sv_string_free`.

use std::slice;

use zeroize::Zeroizing;

use crate::kdbx::{CompositeKey, Database, Entry, Group, KdbxError, ListedEntry};

pub const SV_OK: i32 = 0;
pub const SV_INVALID_ARGUMENT: i32 = 1;
pub const SV_NOT_KDBX: i32 = 2;
pub const SV_KDBX3_UNSUPPORTED: i32 = 3;
pub const SV_UNSUPPORTED_FORMAT: i32 = 4;
pub const SV_INVALID_CREDENTIALS: i32 = 5;
pub const SV_INVALID_KEY_FILE: i32 = 6;
pub const SV_CORRUPTED: i32 = 7;
pub const SV_LIMIT_EXCEEDED: i32 = 8;
pub const SV_NOT_FOUND: i32 = 9;
pub const SV_WRITE_FAILED: i32 = 10;

const UUID_LENGTH: usize = 16;

pub struct SvDatabase {
    database: Database,
}

// The C++ bridge opens and saves the database on a pool thread and reads it
// on the main thread, so the handle must stay Send and Sync.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SvDatabase>();
};

#[repr(C)]
pub struct SvString {
    pub data: *mut u8,
    pub length: usize,
}

/// A serialized database file.
#[repr(C)]
pub struct SvBytes {
    pub data: *mut u8,
    pub length: usize,
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
        KdbxError::Kdbx3Unsupported => SV_KDBX3_UNSUPPORTED,
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
        | KdbxError::RandomUnavailable
        | KdbxError::WriteVerificationFailed => SV_WRITE_FAILED,
        KdbxError::InvalidEntry(_) => SV_INVALID_ARGUMENT,
        KdbxError::UnknownGroup => SV_NOT_FOUND,
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
/// `uuid` must be null or valid for reads of 16 bytes.
unsafe fn read_uuid(uuid: *const u8) -> Option<[u8; UUID_LENGTH]> {
    if uuid.is_null() {
        return None;
    }
    let mut copy = [0u8; UUID_LENGTH];
    copy.copy_from_slice(slice::from_raw_parts(uuid, UUID_LENGTH));
    Some(copy)
}

fn into_sv_string(text: &str) -> SvString {
    let boxed: Box<[u8]> = text.as_bytes().to_vec().into_boxed_slice();
    let length = boxed.len();
    SvString {
        data: Box::into_raw(boxed).cast(),
        length,
    }
}

fn find_entry<'a>(database: &'a Database, uuid: &[u8; UUID_LENGTH]) -> Option<Entry<'a>> {
    database
        .entries()
        .ok()?
        .into_iter()
        .map(|listed| listed.entry)
        .find(|entry| entry.uuid().as_ref() == Some(uuid))
}

fn find_group<'a>(database: &'a Database, uuid: &[u8; UUID_LENGTH]) -> Option<Group<'a>> {
    fn search<'a>(group: Group<'a>, uuid: &[u8; UUID_LENGTH]) -> Option<Group<'a>> {
        if group.uuid().as_ref() == Some(uuid) {
            return Some(group);
        }
        group.groups().find_map(|child| search(child, uuid))
    }
    search(database.root_group().ok()?, uuid)
}

fn field_text(entry: &Entry<'_>, key: &str) -> Zeroizing<String> {
    entry
        .field(key)
        .map(|field| field.value())
        .unwrap_or_default()
}

fn entry_item(entry: &Entry<'_>, group: &Group<'_>) -> Option<ListItem> {
    Some(ListItem {
        uuid: entry.uuid()?,
        is_group: false,
        title: field_text(entry, "Title"),
        user_name: field_text(entry, "UserName"),
        group: group.name(),
    })
}

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

/// Locks the database: drops and zeroizes all decrypted data.
///
/// # Safety
///
/// `database` must be null or a handle from `sv_database_open` that has not
/// been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_database_free(database: *mut SvDatabase) {
    if !database.is_null() {
        drop(Box::from_raw(database));
    }
}

/// Searchable entries matching `query` (all of them for an empty query).
///
/// # Safety
///
/// `database` must be a live handle; `query` null or valid UTF-8 of
/// `query_length` bytes; `out` valid for one write. Release the list with
/// `sv_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_search(
    database: *const SvDatabase,
    query: *const u8,
    query_length: usize,
    out: *mut *mut SvList,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let Some(query) = bytes(query, query_length).and_then(|q| std::str::from_utf8(q).ok()) else {
        return SV_INVALID_ARGUMENT;
    };
    let results = match database.database.search(query) {
        Ok(results) => results,
        Err(error) => return status(error),
    };
    let items = results
        .iter()
        .filter_map(|ListedEntry { entry, group, .. }| entry_item(entry, group))
        .collect();
    *out = Box::into_raw(Box::new(SvList { items }));
    SV_OK
}

/// Subgroups followed by entries of a group, or of the root group when
/// `group_uuid` is null.
///
/// # Safety
///
/// `database` must be a live handle; `group_uuid` null or valid for reads of
/// 16 bytes; `out` valid for one write. Release the list with `sv_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_group(
    database: *const SvDatabase,
    group_uuid: *const u8,
    out: *mut *mut SvList,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let database = &database.database;
    let group = if group_uuid.is_null() {
        database.root_group().ok()
    } else {
        read_uuid(group_uuid).and_then(|uuid| find_group(database, &uuid))
    };
    let Some(group) = group else {
        return SV_NOT_FOUND;
    };
    let mut items: Vec<ListItem> = group
        .groups()
        .filter_map(|child| {
            Some(ListItem {
                uuid: child.uuid()?,
                is_group: true,
                title: child.name(),
                user_name: Zeroizing::new(String::new()),
                group: group.name(),
            })
        })
        .collect();
    items.extend(
        group
            .entries()
            .filter_map(|entry| entry_item(&entry, &group)),
    );
    *out = Box::into_raw(Box::new(SvList { items }));
    SV_OK
}

/// # Safety
///
/// `list` must be null or a list that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_list_length(list: *const SvList) -> usize {
    list.as_ref().map_or(0, |list| list.items.len())
}

/// Copies the 16-byte UUID of item `index` into `uuid_out`.
///
/// # Safety
///
/// `list` must be a live list and `uuid_out` valid for writes of 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn sv_list_uuid(list: *const SvList, index: usize, uuid_out: *mut u8) -> i32 {
    let Some(list) = list.as_ref() else {
        return SV_INVALID_ARGUMENT;
    };
    if uuid_out.is_null() {
        return SV_INVALID_ARGUMENT;
    }
    match list.items.get(index) {
        Some(item) => {
            slice::from_raw_parts_mut(uuid_out, UUID_LENGTH).copy_from_slice(&item.uuid);
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}

/// # Safety
///
/// `list` must be null or a list that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_list_is_group(list: *const SvList, index: usize) -> bool {
    list.as_ref()
        .and_then(|list| list.items.get(index))
        .is_some_and(|item| item.is_group)
}

/// Column 0: title (group name for groups), 1: user name, 2: group name.
///
/// # Safety
///
/// `list` must be a live list and `out` valid for one write. Release the
/// string with `sv_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_list_text(
    list: *const SvList,
    index: usize,
    column: u32,
    out: *mut SvString,
) -> i32 {
    let (Some(list), Some(out)) = (list.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    let Some(item) = list.items.get(index) else {
        return SV_NOT_FOUND;
    };
    let text = match column {
        0 => &item.title,
        1 => &item.user_name,
        2 => &item.group,
        _ => return SV_INVALID_ARGUMENT,
    };
    *out = into_sv_string(text);
    SV_OK
}

/// # Safety
///
/// `list` must be null or a list from this API that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_list_free(list: *mut SvList) {
    if !list.is_null() {
        drop(Box::from_raw(list));
    }
}

/// Field names of an entry and whether each is protected; no values.
///
/// # Safety
///
/// `database` must be a live handle, `entry_uuid` valid for reads of 16
/// bytes and `out` valid for one write. Release with `sv_field_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_fields(
    database: *const SvDatabase,
    entry_uuid: *const u8,
    out: *mut *mut SvFieldList,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let Some(uuid) = read_uuid(entry_uuid) else {
        return SV_INVALID_ARGUMENT;
    };
    let Some(entry) = find_entry(&database.database, &uuid) else {
        return SV_NOT_FOUND;
    };
    let fields = entry
        .fields()
        .map(|field| FieldInfo {
            key: field.key(),
            protected: field.is_protected(),
        })
        .collect();
    *out = Box::into_raw(Box::new(SvFieldList { fields }));
    SV_OK
}

/// # Safety
///
/// `fields` must be null or a field list that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_field_list_length(fields: *const SvFieldList) -> usize {
    fields.as_ref().map_or(0, |fields| fields.fields.len())
}

/// # Safety
///
/// `fields` must be a live field list and `out` valid for one write.
/// Release the string with `sv_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_field_list_key(
    fields: *const SvFieldList,
    index: usize,
    out: *mut SvString,
) -> i32 {
    let (Some(fields), Some(out)) = (fields.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    match fields.fields.get(index) {
        Some(field) => {
            *out = into_sv_string(&field.key);
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}

/// # Safety
///
/// `fields` must be null or a field list that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_field_list_is_protected(
    fields: *const SvFieldList,
    index: usize,
) -> bool {
    fields
        .as_ref()
        .and_then(|fields| fields.fields.get(index))
        .is_some_and(|field| field.protected)
}

/// # Safety
///
/// `fields` must be null or a field list from this API that has not been
/// freed.
#[no_mangle]
pub unsafe extern "C" fn sv_field_list_free(fields: *mut SvFieldList) {
    if !fields.is_null() {
        drop(Box::from_raw(fields));
    }
}

/// The value of one field, for showing or copying it.
///
/// # Safety
///
/// `database` must be a live handle, `entry_uuid` valid for reads of 16
/// bytes, `key` valid UTF-8 of `key_length` bytes and `out` valid for one
/// write. Release the string with `sv_string_free` as soon as possible.
#[no_mangle]
pub unsafe extern "C" fn sv_database_field_value(
    database: *const SvDatabase,
    entry_uuid: *const u8,
    key: *const u8,
    key_length: usize,
    out: *mut SvString,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    let (Some(uuid), Some(key)) = (
        read_uuid(entry_uuid),
        bytes(key, key_length).and_then(|k| std::str::from_utf8(k).ok()),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    let Some(entry) = find_entry(&database.database, &uuid) else {
        return SV_NOT_FOUND;
    };
    match entry.field(key) {
        Some(field) => {
            *out = into_sv_string(&field.value());
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}

/// Adds an entry to the group with `group_uuid` (null for the root group) and
/// writes the entry's UUID to `uuid_out`. `now` is in seconds since the Unix
/// epoch. The change is in memory only until `sv_database_save`.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `group_uuid` and `uuid_out` valid for 16 bytes; `fields` null or valid for
/// reads of `field_count` entries whose key and value pointers follow the
/// rules of `bytes`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_add_entry(
    database: *mut SvDatabase,
    group_uuid: *const u8,
    fields: *const SvField,
    field_count: usize,
    now: i64,
    uuid_out: *mut u8,
) -> i32 {
    let Some(database) = database.as_mut() else {
        return SV_INVALID_ARGUMENT;
    };
    if uuid_out.is_null() || (fields.is_null() && field_count > 0) {
        return SV_INVALID_ARGUMENT;
    }
    let group_uuid = if group_uuid.is_null() {
        database
            .database
            .root_group()
            .ok()
            .and_then(|root| root.uuid())
    } else {
        read_uuid(group_uuid)
    };
    let Some(group_uuid) = group_uuid else {
        return SV_NOT_FOUND;
    };
    let fields = if fields.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(fields, field_count)
    };
    let mut pairs = Vec::with_capacity(fields.len());
    for field in fields {
        let (Some(key), Some(value)) = (
            bytes(field.key, field.key_length).and_then(|k| std::str::from_utf8(k).ok()),
            bytes(field.value, field.value_length).and_then(|v| std::str::from_utf8(v).ok()),
        ) else {
            return SV_INVALID_ARGUMENT;
        };
        pairs.push((key, value));
    }
    match database.database.add_entry(&group_uuid, &pairs, now) {
        Ok(uuid) => {
            slice::from_raw_parts_mut(uuid_out, UUID_LENGTH).copy_from_slice(&uuid);
            SV_OK
        }
        Err(error) => status(error),
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
    *out = SvBytes {
        data: std::ptr::null_mut(),
        length: 0,
    };
    match database.database.save() {
        Ok(file) => {
            let boxed = file.into_boxed_slice();
            out.length = boxed.len();
            out.data = Box::into_raw(boxed).cast();
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Releases a file from `sv_database_save`.
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

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/kdbx4-aes-argon2d.kdbx");
    const PASSWORD: &[u8] = b"sailvault-fixture";

    unsafe fn open(password: &[u8]) -> (i32, *mut SvDatabase) {
        let mut database = std::ptr::null_mut();
        let status = sv_database_open(
            FIXTURE.as_ptr(),
            FIXTURE.len(),
            password.as_ptr(),
            password.len(),
            true,
            std::ptr::null(),
            0,
            &mut database,
        );
        (status, database)
    }

    unsafe fn take(string: SvString) -> String {
        let text = String::from_utf8(slice::from_raw_parts(string.data, string.length).to_vec());
        sv_string_free(string);
        text.unwrap()
    }

    unsafe fn list_text(list: *const SvList, index: usize, column: u32) -> String {
        let mut text = SvString {
            data: std::ptr::null_mut(),
            length: 0,
        };
        assert_eq!(sv_list_text(list, index, column, &mut text), SV_OK);
        take(text)
    }

    #[test]
    fn opens_searches_and_reads_one_field_at_a_time() {
        unsafe {
            let (status, database) = open(PASSWORD);
            assert_eq!(status, SV_OK);

            let mut list = std::ptr::null_mut();
            let query = "alice";
            assert_eq!(
                sv_database_search(database, query.as_ptr(), query.len(), &mut list),
                SV_OK
            );
            assert_eq!(sv_list_length(list), 1);
            assert!(!sv_list_is_group(list, 0));
            assert_eq!(list_text(list, 0, 0), "Example login");
            assert_eq!(list_text(list, 0, 1), "alice@example.org");
            assert_eq!(list_text(list, 0, 2), "Root");
            let mut uuid = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(list, 0, uuid.as_mut_ptr()), SV_OK);
            sv_list_free(list);

            let mut fields = std::ptr::null_mut();
            assert_eq!(
                sv_database_fields(database, uuid.as_ptr(), &mut fields),
                SV_OK
            );
            let mut keys = Vec::new();
            for index in 0..sv_field_list_length(fields) {
                let mut key = SvString {
                    data: std::ptr::null_mut(),
                    length: 0,
                };
                assert_eq!(sv_field_list_key(fields, index, &mut key), SV_OK);
                keys.push((take(key), sv_field_list_is_protected(fields, index)));
            }
            sv_field_list_free(fields);
            assert!(keys.contains(&("Password".to_owned(), true)));
            assert!(keys.contains(&("UserName".to_owned(), false)));

            let mut value = SvString {
                data: std::ptr::null_mut(),
                length: 0,
            };
            let key = "Password";
            assert_eq!(
                sv_database_field_value(
                    database,
                    uuid.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    &mut value
                ),
                SV_OK
            );
            assert_eq!(take(value), "current-password-3");

            sv_database_free(database);
        }
    }

    #[test]
    fn lists_groups_before_entries() {
        unsafe {
            let (_, database) = open(PASSWORD);
            let mut root = std::ptr::null_mut();
            assert_eq!(
                sv_database_group(database, std::ptr::null(), &mut root),
                SV_OK
            );
            let rows: Vec<(bool, String)> = (0..sv_list_length(root))
                .map(|i| (sv_list_is_group(root, i), list_text(root, i, 0)))
                .collect();
            assert_eq!(
                rows,
                [
                    (true, "Banking".to_owned()),
                    (true, "Recycle Bin".to_owned()),
                    (false, "Example login".to_owned()),
                    (false, "Special characters äöü 🔐".to_owned()),
                ]
            );
            let mut banking = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(root, 0, banking.as_mut_ptr()), SV_OK);
            sv_list_free(root);

            let mut children = std::ptr::null_mut();
            assert_eq!(
                sv_database_group(database, banking.as_ptr(), &mut children),
                SV_OK
            );
            assert_eq!(sv_list_length(children), 1);
            assert_eq!(list_text(children, 0, 0), "Cards");
            sv_list_free(children);
            sv_database_free(database);
        }
    }

    #[test]
    fn reports_errors_and_rejects_null_arguments() {
        unsafe {
            let (status, database) = open(b"wrong");
            assert_eq!(status, SV_INVALID_CREDENTIALS);
            assert!(database.is_null());

            let mut out = std::ptr::null_mut();
            assert_eq!(
                sv_database_open(
                    std::ptr::null(),
                    10,
                    std::ptr::null(),
                    0,
                    true,
                    std::ptr::null(),
                    0,
                    &mut out
                ),
                SV_INVALID_ARGUMENT
            );
            assert_eq!(
                sv_database_search(
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    &mut std::ptr::null_mut()
                ),
                SV_INVALID_ARGUMENT
            );
            assert_eq!(sv_list_length(std::ptr::null()), 0);
            sv_database_free(std::ptr::null_mut());
            sv_list_free(std::ptr::null_mut());
            sv_string_free(SvString {
                data: std::ptr::null_mut(),
                length: 0,
            });
            sv_bytes_free(SvBytes {
                data: std::ptr::null_mut(),
                length: 0,
            });
        }
    }

    #[test]
    fn adds_an_entry_and_saves_a_file_that_opens_again() {
        unsafe {
            let (status, database) = open(PASSWORD);
            assert_eq!(status, SV_OK);
            let mut root = std::ptr::null_mut();
            assert_eq!(
                sv_database_group(database, std::ptr::null(), &mut root),
                SV_OK
            );
            let mut root_uuid = [0u8; UUID_LENGTH];
            let root_index = sv_list_length(root) - 1;
            assert_eq!(
                sv_list_uuid(root, root_index, root_uuid.as_mut_ptr()),
                SV_OK
            );
            sv_list_free(root);
            let group_uuid = (*database).database.root_group().unwrap().uuid().unwrap();

            let field = |key: &'static str, value: &'static str| SvField {
                key: key.as_ptr(),
                key_length: key.len(),
                value: value.as_ptr(),
                value_length: value.len(),
            };
            let fields = [field("Title", "Via FFI"), field("Password", "ffi-secret")];
            let mut uuid = [0u8; UUID_LENGTH];
            assert_eq!(
                sv_database_add_entry(
                    database,
                    group_uuid.as_ptr(),
                    fields.as_ptr(),
                    fields.len(),
                    1_767_261_600,
                    uuid.as_mut_ptr()
                ),
                SV_OK
            );
            assert_eq!(
                sv_database_add_entry(
                    database,
                    [0xEE; UUID_LENGTH].as_ptr(),
                    fields.as_ptr(),
                    fields.len(),
                    0,
                    uuid.as_mut_ptr()
                ),
                SV_NOT_FOUND
            );

            let mut file = SvBytes {
                data: std::ptr::null_mut(),
                length: 0,
            };
            assert_eq!(sv_database_save(database, &mut file), SV_OK);
            let saved = slice::from_raw_parts(file.data, file.length).to_vec();
            sv_bytes_free(file);
            sv_database_free(database);

            let mut reopened = std::ptr::null_mut();
            assert_eq!(
                sv_database_open(
                    saved.as_ptr(),
                    saved.len(),
                    PASSWORD.as_ptr(),
                    PASSWORD.len(),
                    true,
                    std::ptr::null(),
                    0,
                    &mut reopened
                ),
                SV_OK
            );
            let mut value = SvString {
                data: std::ptr::null_mut(),
                length: 0,
            };
            let key = "Password";
            assert_eq!(
                sv_database_field_value(
                    reopened,
                    uuid.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    &mut value
                ),
                SV_OK
            );
            assert_eq!(take(value), "ffi-secret");
            sv_database_free(reopened);
        }
    }
}
