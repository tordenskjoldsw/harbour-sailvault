use super::{deliver, field_pairs, read_uuid, status, utf8, write_uuid, SvDatabase, SvField};
use super::{SV_INVALID_ARGUMENT, SV_NOT_FOUND, SV_OK, UUID_LENGTH};
use crate::kdbx::Database;

/// # Safety
///
/// `group_uuid` must be null (the root group) or valid for reads of 16 bytes.
unsafe fn group_or_root(database: &Database, group_uuid: *const u8) -> Option<[u8; UUID_LENGTH]> {
    if group_uuid.is_null() {
        database.root_group().ok()?.uuid()
    } else {
        read_uuid(group_uuid)
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
    let Some(group_uuid) = group_or_root(&database.database, group_uuid) else {
        return SV_NOT_FOUND;
    };
    match database.database.add_entry(&group_uuid, &pairs, now) {
        Ok(uuid) => {
            write_uuid(uuid_out, &uuid);
            SV_OK
        }
        Err(error) => status(error),
    }
}

/// Adds a group named `name` to the group with `parent_uuid` (null for the
/// root group) and writes its UUID to `uuid_out`. Refused inside the
/// recycle bin and for an empty name.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `parent_uuid` null or valid for 16 bytes; `name` valid UTF-8 of
/// `name_length` bytes; `uuid_out` valid for writes of 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn sv_database_add_group(
    database: *mut SvDatabase,
    parent_uuid: *const u8,
    name: *const u8,
    name_length: usize,
    now: i64,
    uuid_out: *mut u8,
) -> i32 {
    let (Some(database), Some(name)) = (database.as_mut(), utf8(name, name_length)) else {
        return SV_INVALID_ARGUMENT;
    };
    if uuid_out.is_null() {
        return SV_INVALID_ARGUMENT;
    }
    let Some(parent_uuid) = group_or_root(&database.database, parent_uuid) else {
        return SV_NOT_FOUND;
    };
    match database.database.add_group(&parent_uuid, name, now) {
        Ok(uuid) => {
            write_uuid(uuid_out, &uuid);
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
    deliver(
        database.database.update_entry(&uuid, &pairs, now),
        changed_out,
    )
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
    deliver(
        database.database.move_entry(&entry_uuid, &group_uuid, now),
        moved_out,
    )
}

/// Moves the entry or group with `uuid` to the recycle bin, or removes it
/// for good when it is already there or the recycle bin is disabled (see
/// `Database::delete_item`). `permanent_out` receives which happened.
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
    deliver(database.database.delete_item(&uuid, now), permanent_out)
}

/// Renames a group (see `Database::rename_group`); `changed_out` receives
/// whether the name changed.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `group_uuid` valid for 16 bytes; `name` valid UTF-8 of `name_length`
/// bytes; `changed_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_rename_group(
    database: *mut SvDatabase,
    group_uuid: *const u8,
    name: *const u8,
    name_length: usize,
    now: i64,
    changed_out: *mut bool,
) -> i32 {
    let (Some(database), Some(uuid), Some(name), Some(changed_out)) = (
        database.as_mut(),
        read_uuid(group_uuid),
        utf8(name, name_length),
        changed_out.as_mut(),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    deliver(
        database.database.rename_group(&uuid, name, now),
        changed_out,
    )
}

/// Moves a group with its content into another group (see
/// `Database::move_group`); `moved_out` receives whether it moved.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `group_uuid` and `parent_uuid` valid for 16 bytes; `moved_out` valid for
/// one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_move_group(
    database: *mut SvDatabase,
    group_uuid: *const u8,
    parent_uuid: *const u8,
    now: i64,
    moved_out: *mut bool,
) -> i32 {
    let (Some(database), Some(uuid), Some(parent), Some(moved_out)) = (
        database.as_mut(),
        read_uuid(group_uuid),
        read_uuid(parent_uuid),
        moved_out.as_mut(),
    ) else {
        return SV_INVALID_ARGUMENT;
    };
    deliver(database.database.move_group(&uuid, &parent, now), moved_out)
}

/// Moves an entry or group out of the recycle bin (see
/// `Database::restore`).
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread; `uuid`
/// valid for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn sv_database_restore(
    database: *mut SvDatabase,
    uuid: *const u8,
    now: i64,
) -> i32 {
    let (Some(database), Some(uuid)) = (database.as_mut(), read_uuid(uuid)) else {
        return SV_INVALID_ARGUMENT;
    };
    match database.database.restore(&uuid, now) {
        Ok(_) => SV_OK,
        Err(error) => status(error),
    }
}

/// Removes everything in the recycle bin for good (see
/// `Database::empty_recycle_bin`); `changed_out` receives whether anything
/// was removed.
///
/// # Safety
///
/// `database` must be a live handle not in use by another thread;
/// `changed_out` valid for one write.
#[no_mangle]
pub unsafe extern "C" fn sv_database_empty_recycle_bin(
    database: *mut SvDatabase,
    now: i64,
    changed_out: *mut bool,
) -> i32 {
    let (Some(database), Some(changed_out)) = (database.as_mut(), changed_out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    deliver(database.database.empty_recycle_bin(now), changed_out)
}
