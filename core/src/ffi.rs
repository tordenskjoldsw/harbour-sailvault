//! C API for the C++ bridge, declared in `include/sailvault_core.h`.
//!
//! The database stays in Rust behind an opaque handle. Lists carry ids,
//! titles, user names and group names; field values cross the boundary one
//! at a time, when the user shows or copies them. Every string handed out is
//! zeroized by `sv_string_free`.

use std::slice;

use zeroize::Zeroizing;

use crate::kdbx::{CompositeKey, Database, Entry, Group, KdbxError, ListedEntry};
use crate::password::{self, CharacterClasses, PasswordError};

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
pub const SV_RANDOM_UNAVAILABLE: i32 = 11;

pub const SV_CLASS_LOWER: u32 = 1;
pub const SV_CLASS_UPPER: u32 = 2;
pub const SV_CLASS_DIGITS: u32 = 4;
pub const SV_CLASS_SYMBOLS: u32 = 8;

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
        KdbxError::CompressionFailed | KdbxError::WriteVerificationFailed => SV_WRITE_FAILED,
        KdbxError::RandomUnavailable => SV_RANDOM_UNAVAILABLE,
        KdbxError::InvalidEntry(_) | KdbxError::RootGroupProtected => SV_INVALID_ARGUMENT,
        KdbxError::UnknownGroup | KdbxError::UnknownEntry => SV_NOT_FOUND,
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
            let key = std::str::from_utf8(bytes(field.key, field.key_length)?).ok()?;
            let value = std::str::from_utf8(bytes(field.value, field.value_length)?).ok()?;
            Some((key, value))
        })
        .collect()
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

/// Every group outside the recycle bin, parents before children, for picking
/// a target group. The group column holds the path of the parent groups.
///
/// # Safety
///
/// `database` must be a live handle and `out` valid for one write. Release
/// the list with `sv_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_groups(
    database: *const SvDatabase,
    out: *mut *mut SvList,
) -> i32 {
    fn collect(
        group: Group<'_>,
        path: &str,
        recycle_bin: Option<[u8; UUID_LENGTH]>,
        items: &mut Vec<ListItem>,
    ) {
        let Some(uuid) = group.uuid() else {
            return;
        };
        if Some(uuid) == recycle_bin {
            return;
        }
        let name = group.name();
        let child_path = Zeroizing::new(if path.is_empty() {
            name.to_string()
        } else {
            format!("{path} / {}", name.as_str())
        });
        items.push(ListItem {
            uuid,
            is_group: true,
            title: name,
            user_name: Zeroizing::new(String::new()),
            group: Zeroizing::new(path.to_owned()),
        });
        for child in group.groups() {
            collect(child, &child_path, recycle_bin, items);
        }
    }

    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let database = &database.database;
    let root = match database.root_group() {
        Ok(root) => root,
        Err(error) => return status(error),
    };
    let mut items = Vec::new();
    collect(root, "", database.recycle_bin(), &mut items);
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
    let (Some(database), Some(pairs)) = (database.as_mut(), field_pairs(fields, field_count))
    else {
        return SV_INVALID_ARGUMENT;
    };
    if uuid_out.is_null() {
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
    match database.database.add_entry(&group_uuid, &pairs, now) {
        Ok(uuid) => {
            slice::from_raw_parts_mut(uuid_out, UUID_LENGTH).copy_from_slice(&uuid);
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Sets fields of the entry with `entry_uuid` (see `Database::update_entry`).
/// `changed_out` receives whether anything changed, so the caller knows
/// whether a save is due.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `entry_uuid` valid for 16 bytes; `fields` as for `sv_database_add_entry`;
/// `changed_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_update_entry(
    database: *mut SvDatabase,
    entry_uuid: *const u8,
    fields: *const SvField,
    field_count: usize,
    now: i64,
    changed_out: *mut bool,
) -> i32 {
    let (Some(database), Some(uuid), Some(pairs), Some(changed_out)) = (
        database.as_mut(),
        read_uuid(entry_uuid),
        field_pairs(fields, field_count),
        changed_out.as_mut(),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    *changed_out = false;
    match database.database.update_entry(&uuid, &pairs, now) {
        Ok(changed) => {
            *changed_out = changed;
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Moves the entry with `entry_uuid` into the group with `group_uuid` (see
/// `Database::move_entry`). `moved_out` receives whether it moved.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `entry_uuid` and `group_uuid` valid for 16 bytes; `moved_out` valid for
/// one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_move_entry(
    database: *mut SvDatabase,
    entry_uuid: *const u8,
    group_uuid: *const u8,
    now: i64,
    moved_out: *mut bool,
) -> i32 {
    let (Some(database), Some(entry_uuid), Some(group_uuid), Some(moved_out)) = (
        database.as_mut(),
        read_uuid(entry_uuid),
        read_uuid(group_uuid),
        moved_out.as_mut(),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    *moved_out = false;
    match database.database.move_entry(&entry_uuid, &group_uuid, now) {
        Ok(moved) => {
            *moved_out = moved;
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Moves the entry or group with `uuid` to the recycle bin, or removes it
/// for good when it is already there or the recycle bin is disabled (see
/// `Database::delete_entry` and `delete_group`). `permanent_out` receives
/// which happened. UUIDs are unique across entries and groups.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread; `uuid`
/// valid for 16 bytes; `permanent_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_delete_item(
    database: *mut SvDatabase,
    uuid: *const u8,
    now: i64,
    permanent_out: *mut bool,
) -> i32 {
    let (Some(database), Some(uuid), Some(permanent_out)) =
        (database.as_mut(), read_uuid(uuid), permanent_out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    *permanent_out = false;
    let result = match database.database.delete_entry(&uuid, now) {
        Err(KdbxError::UnknownEntry) => database.database.delete_group(&uuid, now),
        result => result,
    };
    match result {
        Ok(permanent) => {
            *permanent_out = permanent;
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Whether `sv_database_delete_item` would remove the item for good.
///
/// # Safety
///
/// `database` must be a live handle; `uuid` valid for 16 bytes; `out` valid
/// for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_delete_is_permanent(
    database: *const SvDatabase,
    uuid: *const u8,
    out: *mut bool,
) -> i32 {
    let (Some(database), Some(uuid), Some(out)) =
        (database.as_ref(), read_uuid(uuid), out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    *out = false;
    match database.database.deletes_permanently(&uuid) {
        Ok(permanent) => {
            *out = permanent;
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
    *out = SvString {
        data: std::ptr::null_mut(),
        length: 0,
    };
    let classes = CharacterClasses {
        lower: classes & SV_CLASS_LOWER != 0,
        upper: classes & SV_CLASS_UPPER != 0,
        digits: classes & SV_CLASS_DIGITS != 0,
        symbols: classes & SV_CLASS_SYMBOLS != 0,
    };
    match password::generate(length, classes) {
        Ok(password) => {
            *out = into_sv_string(&password);
            SV_OK
        }
        Err(PasswordError::InvalidParameters) => SV_INVALID_ARGUMENT,
        Err(PasswordError::RandomUnavailable) => SV_RANDOM_UNAVAILABLE,
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
    fn updates_and_deletes_entries() {
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
            let mut uuid = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(list, 0, uuid.as_mut_ptr()), SV_OK);
            sv_list_free(list);

            let key = "Password";
            let value = "rotated";
            let field = SvField {
                key: key.as_ptr(),
                key_length: key.len(),
                value: value.as_ptr(),
                value_length: value.len(),
            };
            let mut changed = false;
            assert_eq!(
                sv_database_update_entry(database, uuid.as_ptr(), &field, 1, 0, &mut changed),
                SV_OK
            );
            assert!(changed);
            assert_eq!(
                sv_database_update_entry(database, uuid.as_ptr(), &field, 1, 0, &mut changed),
                SV_OK
            );
            assert!(!changed);
            let mut shown = SvString {
                data: std::ptr::null_mut(),
                length: 0,
            };
            assert_eq!(
                sv_database_field_value(
                    database,
                    uuid.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    &mut shown
                ),
                SV_OK
            );
            assert_eq!(take(shown), "rotated");

            let mut permanent = true;
            assert_eq!(
                sv_database_delete_is_permanent(database, uuid.as_ptr(), &mut permanent),
                SV_OK
            );
            assert!(!permanent);
            assert_eq!(
                sv_database_delete_item(database, uuid.as_ptr(), 0, &mut permanent),
                SV_OK
            );
            assert!(!permanent);
            assert_eq!(
                sv_database_delete_item(database, uuid.as_ptr(), 0, &mut permanent),
                SV_OK
            );
            assert!(permanent);
            assert_eq!(
                sv_database_delete_item(database, uuid.as_ptr(), 0, &mut permanent),
                SV_NOT_FOUND
            );

            let mut root = std::ptr::null_mut();
            assert_eq!(
                sv_database_group(database, std::ptr::null(), &mut root),
                SV_OK
            );
            assert!(sv_list_is_group(root, 0));
            let mut group = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(root, 0, group.as_mut_ptr()), SV_OK);
            sv_list_free(root);
            assert_eq!(
                sv_database_delete_is_permanent(database, group.as_ptr(), &mut permanent),
                SV_OK
            );
            assert!(!permanent);
            assert_eq!(
                sv_database_delete_item(database, group.as_ptr(), 0, &mut permanent),
                SV_OK
            );
            assert!(!permanent);
            assert_eq!(
                sv_database_delete_is_permanent(database, group.as_ptr(), &mut permanent),
                SV_OK
            );
            assert!(permanent);
            sv_database_free(database);
        }
    }

    #[test]
    fn lists_move_targets_and_moves_an_entry() {
        unsafe {
            let (status, database) = open(PASSWORD);
            assert_eq!(status, SV_OK);
            let mut groups = std::ptr::null_mut();
            assert_eq!(sv_database_groups(database, &mut groups), SV_OK);
            let rows: Vec<(String, String)> = (0..sv_list_length(groups))
                .map(|index| (list_text(groups, index, 0), list_text(groups, index, 2)))
                .collect();
            assert_eq!(
                rows,
                [
                    ("Root".to_owned(), String::new()),
                    ("Banking".to_owned(), "Root".to_owned()),
                    ("Cards".to_owned(), "Root / Banking".to_owned()),
                ]
            );
            let mut cards = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(groups, 2, cards.as_mut_ptr()), SV_OK);
            sv_list_free(groups);

            let mut list = std::ptr::null_mut();
            let query = "alice";
            assert_eq!(
                sv_database_search(database, query.as_ptr(), query.len(), &mut list),
                SV_OK
            );
            let mut entry = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(list, 0, entry.as_mut_ptr()), SV_OK);
            sv_list_free(list);

            let mut moved = false;
            assert_eq!(
                sv_database_move_entry(database, entry.as_ptr(), cards.as_ptr(), 0, &mut moved),
                SV_OK
            );
            assert!(moved);
            assert_eq!(
                sv_database_move_entry(database, entry.as_ptr(), cards.as_ptr(), 0, &mut moved),
                SV_OK
            );
            assert!(!moved);
            assert_eq!(
                sv_database_move_entry(database, cards.as_ptr(), cards.as_ptr(), 0, &mut moved),
                SV_NOT_FOUND
            );

            let mut content = std::ptr::null_mut();
            assert_eq!(
                sv_database_group(database, cards.as_ptr(), &mut content),
                SV_OK
            );
            let last = sv_list_length(content) - 1;
            let mut listed = [0u8; UUID_LENGTH];
            assert_eq!(sv_list_uuid(content, last, listed.as_mut_ptr()), SV_OK);
            assert_eq!(listed, entry);
            sv_list_free(content);
            sv_database_free(database);
        }
    }

    #[test]
    fn generates_passwords_from_the_requested_classes() {
        unsafe {
            let mut password = SvString {
                data: std::ptr::null_mut(),
                length: 0,
            };
            assert_eq!(
                sv_generate_password(16, SV_CLASS_UPPER | SV_CLASS_DIGITS, &mut password),
                SV_OK
            );
            let text = take(password);
            assert_eq!(text.len(), 16);
            assert!(text
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
            let mut rejected = SvString {
                data: std::ptr::null_mut(),
                length: 0,
            };
            assert_eq!(
                sv_generate_password(16, 0, &mut rejected),
                SV_INVALID_ARGUMENT
            );
            assert_eq!(
                sv_generate_password(16, SV_CLASS_LOWER, std::ptr::null_mut()),
                SV_INVALID_ARGUMENT
            );
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
