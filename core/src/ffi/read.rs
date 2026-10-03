use zeroize::Zeroizing;

use super::{deliver, read_uuid, status, utf8, write_uuid, FieldInfo, ListItem};
use super::{SvDatabase, SvFieldList, SvList, SvString, UUID_LENGTH};
use super::{SV_COLUMN_GROUP, SV_COLUMN_TITLE, SV_COLUMN_USER_NAME};
use super::{SV_INVALID_ARGUMENT, SV_NOT_FOUND, SV_OK};
use crate::kdbx::{Database, Entry, Group, ListedEntry};

/// The current state of an entry for `SV_CURRENT_VERSION`, or its history
/// item at index `version`, oldest first.
fn find_version<'a>(
    database: &'a Database,
    uuid: &[u8; UUID_LENGTH],
    version: i64,
) -> Option<Entry<'a>> {
    let entry = database.entry(uuid)?;
    match usize::try_from(version) {
        Ok(index) => entry.history().nth(index),
        Err(_) => Some(entry),
    }
}

fn field_text(entry: Entry<'_>, key: &str) -> Zeroizing<String> {
    entry
        .field(key)
        .map(|field| field.value())
        .unwrap_or_default()
}

fn entry_item(entry: Entry<'_>, group: Group<'_>) -> Option<ListItem> {
    Some(ListItem {
        uuid: entry.uuid()?,
        is_group: false,
        title: field_text(entry, "Title"),
        user_name: field_text(entry, "UserName"),
        group: group.name(),
    })
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
    let Some(query) = utf8(query, query_length) else {
        return SV_INVALID_ARGUMENT;
    };
    let results = match database.database.search(query) {
        Ok(results) => results,
        Err(error) => return status(error),
    };
    let items = results
        .iter()
        .filter_map(|ListedEntry { entry, group, .. }| entry_item(*entry, *group))
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
        read_uuid(group_uuid).and_then(|uuid| database.group(&uuid))
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
    items.extend(group.entries().filter_map(|entry| entry_item(entry, group)));
    *out = Box::into_raw(Box::new(SvList { items }));
    SV_OK
}

/// Every group outside the recycle bin, parents before children, for picking
/// a target group; without the group `exclude_uuid` and its subgroups when
/// it is not null, so a group is never offered as its own target. The group
/// column holds the path of the parent groups.
///
/// # Safety
///
/// `database` must be a live handle, `exclude_uuid` null or valid for reads
/// of 16 bytes and `out` valid for one write. Release the list with
/// `sv_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_groups(
    database: *const SvDatabase,
    exclude_uuid: *const u8,
    out: *mut *mut SvList,
) -> i32 {
    fn collect(
        group: Group<'_>,
        path: &str,
        skipped: [Option<[u8; UUID_LENGTH]>; 2],
        items: &mut Vec<ListItem>,
    ) {
        let Some(uuid) = group.uuid() else {
            return;
        };
        if skipped.contains(&Some(uuid)) {
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
            collect(child, &child_path, skipped, items);
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
    collect(
        root,
        "",
        [database.recycle_bin(), read_uuid(exclude_uuid)],
        &mut items,
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
            write_uuid(uuid_out, &item.uuid);
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

/// `SV_COLUMN_*`: title (group name for groups), user name, group name.
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
    *out = SvString::EMPTY;
    let Some(item) = list.items.get(index) else {
        return SV_NOT_FOUND;
    };
    let text = match column {
        SV_COLUMN_TITLE => &item.title,
        SV_COLUMN_USER_NAME => &item.user_name,
        SV_COLUMN_GROUP => &item.group,
        _ => return SV_INVALID_ARGUMENT,
    };
    *out = SvString::new(text);
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

/// Field names of an entry, or of its history item `version` (-1 for the
/// current state), and whether each is protected; no values.
///
/// # Safety
///
/// `database` must be a live handle, `entry_uuid` valid for reads of 16
/// bytes and `out` valid for one write. Release with `sv_field_list_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_fields(
    database: *const SvDatabase,
    entry_uuid: *const u8,
    version: i64,
    out: *mut *mut SvFieldList,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let Some(uuid) = read_uuid(entry_uuid) else {
        return SV_INVALID_ARGUMENT;
    };
    let Some(entry) = find_version(&database.database, &uuid, version) else {
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
    *out = SvString::EMPTY;
    match fields.fields.get(index) {
        Some(field) => {
            *out = SvString::new(&field.key);
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

/// The value of one field of an entry, or of its history item `version` (-1
/// for the current state), for showing or copying it.
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
    version: i64,
    key: *const u8,
    key_length: usize,
    out: *mut SvString,
) -> i32 {
    let (Some(database), Some(out)) = (database.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = SvString::EMPTY;
    let (Some(uuid), Some(key)) = (read_uuid(entry_uuid), utf8(key, key_length)) else {
        return SV_INVALID_ARGUMENT;
    };
    let Some(entry) = find_version(&database.database, &uuid, version) else {
        return SV_NOT_FOUND;
    };
    match entry.field(key) {
        Some(field) => {
            *out = SvString::new(&field.value());
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}

/// Whether the entry or group with `uuid` is the recycle bin or inside it.
///
/// # Safety
///
/// `database` must be a live handle; `uuid` valid for 16 bytes; `out` valid
/// for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_in_recycle_bin(
    database: *const SvDatabase,
    uuid: *const u8,
    out: *mut bool,
) -> i32 {
    let (Some(database), Some(uuid), Some(out)) =
        (database.as_ref(), read_uuid(uuid), out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    deliver(database.database.in_recycle_bin(&uuid), out)
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
    deliver(database.database.deletes_permanently(&uuid), out)
}

/// The number of history items of an entry.
///
/// # Safety
///
/// `database` must be a live handle, `entry_uuid` valid for reads of 16
/// bytes and `out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_history_length(
    database: *const SvDatabase,
    entry_uuid: *const u8,
    out: *mut usize,
) -> i32 {
    let (Some(database), Some(uuid), Some(out)) =
        (database.as_ref(), read_uuid(entry_uuid), out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    *out = 0;
    match database.database.entry(&uuid) {
        Some(entry) => {
            *out = entry.history().count();
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}

/// The modification time of an entry's history item `version`, or of the
/// entry for -1, in seconds since the Unix epoch.
///
/// # Safety
///
/// `database` must be a live handle, `entry_uuid` valid for reads of 16
/// bytes and `out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_modification_time(
    database: *const SvDatabase,
    entry_uuid: *const u8,
    version: i64,
    out: *mut i64,
) -> i32 {
    let (Some(database), Some(uuid), Some(out)) =
        (database.as_ref(), read_uuid(entry_uuid), out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    *out = 0;
    match find_version(&database.database, &uuid, version).and_then(|e| e.modification_time()) {
        Some(time) => {
            *out = time;
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}

/// Writes the recycle bin's UUID to `uuid_out`; `SV_NOT_FOUND` when the
/// database has none.
///
/// # Safety
///
/// `database` must be a live handle and `uuid_out` valid for writes of 16
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv_database_recycle_bin(
    database: *const SvDatabase,
    uuid_out: *mut u8,
) -> i32 {
    let Some(database) = database.as_ref() else {
        return SV_INVALID_ARGUMENT;
    };
    if uuid_out.is_null() {
        return SV_INVALID_ARGUMENT;
    }
    match database.database.existing_recycle_bin() {
        Some(bin) => {
            write_uuid(uuid_out, &bin);
            SV_OK
        }
        None => SV_NOT_FOUND,
    }
}
