use super::bitwarden::*;
use super::database::*;
use super::edit::*;
use super::password::*;
use super::read::*;
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/kdbx4-aes-argon2d.kdbx");
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
    let mut text = SvString::EMPTY;
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
            sv_database_fields(database, uuid.as_ptr(), -1, &mut fields),
            SV_OK
        );
        let mut keys = Vec::new();
        for index in 0..sv_field_list_length(fields) {
            let mut key = SvString::EMPTY;
            assert_eq!(sv_field_list_key(fields, index, &mut key), SV_OK);
            keys.push((take(key), sv_field_list_is_protected(fields, index)));
        }
        sv_field_list_free(fields);
        assert!(keys.contains(&("Password".to_owned(), true)));
        assert!(keys.contains(&("UserName".to_owned(), false)));

        let mut value = SvString::EMPTY;
        let key = "Password";
        assert_eq!(
            sv_database_field_value(
                database,
                uuid.as_ptr(),
                -1,
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
        sv_string_free(SvString::EMPTY);
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
        let mut shown = SvString::EMPTY;
        assert_eq!(
            sv_database_field_value(
                database,
                uuid.as_ptr(),
                -1,
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
        assert_eq!(
            sv_database_groups(database, std::ptr::null(), &mut groups),
            SV_OK
        );
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

        let name = "Mail";
        let mut mail = [0u8; UUID_LENGTH];
        assert_eq!(
            sv_database_add_group(
                database,
                std::ptr::null(),
                name.as_ptr(),
                name.len(),
                0,
                mail.as_mut_ptr()
            ),
            SV_OK
        );
        let mut inside = true;
        assert_eq!(
            sv_database_in_recycle_bin(database, mail.as_ptr(), &mut inside),
            SV_OK
        );
        assert!(!inside);
        let mut groups = std::ptr::null_mut();
        assert_eq!(
            sv_database_groups(database, std::ptr::null(), &mut groups),
            SV_OK
        );
        assert_eq!(list_text(groups, sv_list_length(groups) - 1, 0), "Mail");
        sv_list_free(groups);
        assert_eq!(
            sv_database_add_group(
                database,
                std::ptr::null(),
                name.as_ptr(),
                0,
                0,
                mail.as_mut_ptr()
            ),
            SV_INVALID_ARGUMENT
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
fn imports_a_bitwarden_export_into_the_root_group() {
    const EXPORT: &[u8] = include_bytes!("../../tests/vectors/bitwarden_unencrypted.json");
    unsafe {
        let mut kind = -1;
        assert_eq!(
            sv_bitwarden_export_kind(EXPORT.as_ptr(), EXPORT.len(), &mut kind),
            SV_OK
        );
        assert_eq!(kind, SV_EXPORT_UNENCRYPTED);
        let not_json = b"{}";
        assert_eq!(
            sv_bitwarden_export_kind(not_json.as_ptr(), not_json.len(), &mut kind),
            SV_NOT_AN_EXPORT
        );

        let name = "Bitwarden import";
        let mut import = std::ptr::null_mut();
        assert_eq!(
            sv_bitwarden_read(
                EXPORT.as_ptr(),
                EXPORT.len(),
                std::ptr::null(),
                0,
                false,
                name.as_ptr(),
                name.len(),
                &mut import
            ),
            SV_OK
        );

        let (status, database) = open(PASSWORD);
        assert_eq!(status, SV_OK);
        let (mut added, mut updated) = (0, 0);
        assert_eq!(
            sv_database_import(database, import, 0, &mut added, &mut updated),
            SV_OK
        );
        assert_eq!((added, updated), (4, 0));
        assert_eq!(
            sv_database_import(database, import, 0, &mut added, &mut updated),
            SV_OK
        );
        assert_eq!((added, updated), (0, 0));
        sv_import_free(import);

        let mut groups = std::ptr::null_mut();
        assert_eq!(
            sv_database_groups(database, std::ptr::null(), &mut groups),
            SV_OK
        );
        let names: Vec<String> = (0..sv_list_length(groups))
            .map(|index| list_text(groups, index, 0))
            .collect();
        assert_eq!(
            names
                .iter()
                .filter(|name| *name == "Bitwarden import")
                .count(),
            1
        );
        sv_list_free(groups);
        sv_database_free(database);
    }
}

#[test]
fn reads_history_items_and_manages_the_recycle_bin() {
    unsafe {
        let (status, database) = open(PASSWORD);
        assert_eq!(status, SV_OK);
        let mut list = std::ptr::null_mut();
        let query = "alice";
        assert_eq!(
            sv_database_search(database, query.as_ptr(), query.len(), &mut list),
            SV_OK
        );
        let mut entry = [0u8; UUID_LENGTH];
        assert_eq!(sv_list_uuid(list, 0, entry.as_mut_ptr()), SV_OK);
        sv_list_free(list);

        let mut length = 0;
        assert_eq!(
            sv_database_history_length(database, entry.as_ptr(), &mut length),
            SV_OK
        );
        assert_eq!(length, 2);
        let key = "Password";
        let mut value = SvString::EMPTY;
        assert_eq!(
            sv_database_field_value(
                database,
                entry.as_ptr(),
                0,
                key.as_ptr(),
                key.len(),
                &mut value
            ),
            SV_OK
        );
        assert_eq!(take(value), "old-password-1");
        let (mut oldest, mut current) = (0, 0);
        assert_eq!(
            sv_database_modification_time(database, entry.as_ptr(), 0, &mut oldest),
            SV_OK
        );
        assert_eq!(
            sv_database_modification_time(database, entry.as_ptr(), -1, &mut current),
            SV_OK
        );
        assert!(oldest < current);
        assert_eq!(
            sv_database_modification_time(database, entry.as_ptr(), 2, &mut oldest),
            SV_NOT_FOUND
        );

        let mut bin = [0u8; UUID_LENGTH];
        assert_eq!(sv_database_recycle_bin(database, bin.as_mut_ptr()), SV_OK);
        let mut permanent = true;
        assert_eq!(
            sv_database_delete_item(database, entry.as_ptr(), 0, &mut permanent),
            SV_OK
        );
        assert_eq!(sv_database_restore(database, entry.as_ptr(), 0), SV_OK);
        assert_eq!(
            sv_database_restore(database, entry.as_ptr(), 0),
            SV_INVALID_ARGUMENT
        );
        let mut changed = false;
        assert_eq!(
            sv_database_empty_recycle_bin(database, 0, &mut changed),
            SV_OK
        );
        assert!(changed);
        let mut content = std::ptr::null_mut();
        assert_eq!(
            sv_database_group(database, bin.as_ptr(), &mut content),
            SV_OK
        );
        assert_eq!(sv_list_length(content), 0);
        sv_list_free(content);
        sv_database_free(database);
    }
}

#[test]
fn creates_a_database_that_opens_with_its_password() {
    unsafe {
        let name = "Passwords";
        let mut database = std::ptr::null_mut();
        let mut file = SvBytes {
            data: std::ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            sv_database_create(
                PASSWORD.as_ptr(),
                0,
                name.as_ptr(),
                name.len(),
                SV_KDF_STANDARD,
                0,
                &mut database,
                &mut file
            ),
            SV_INVALID_ARGUMENT
        );
        assert_eq!(
            sv_database_create(
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                name.as_ptr(),
                name.len(),
                SV_KDF_STANDARD,
                0,
                &mut database,
                &mut file
            ),
            SV_OK
        );
        let mut reopened = std::ptr::null_mut();
        assert_eq!(
            sv_database_open(
                file.data,
                file.length,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                true,
                std::ptr::null(),
                0,
                &mut reopened
            ),
            SV_OK
        );
        let mut root = std::ptr::null_mut();
        assert_eq!(
            sv_database_group(database, std::ptr::null(), &mut root),
            SV_OK
        );
        assert_eq!(sv_list_length(root), 0);
        sv_list_free(root);
        sv_bytes_free(file);
        sv_database_free(reopened);
        sv_database_free(database);
    }
}

#[test]
fn generates_passwords_from_the_requested_classes() {
    unsafe {
        let mut password = SvString::EMPTY;
        assert_eq!(
            sv_generate_password(16, SV_CLASS_UPPER | SV_CLASS_DIGITS, &mut password),
            SV_OK
        );
        let text = take(password);
        assert_eq!(text.len(), 16);
        assert!(text
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        let mut rejected = SvString::EMPTY;
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
        let mut value = SvString::EMPTY;
        let key = "Password";
        assert_eq!(
            sv_database_field_value(
                reopened,
                uuid.as_ptr(),
                -1,
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

#[test]
fn renames_and_moves_groups() {
    unsafe {
        let (_, database) = open(PASSWORD);
        let add = |name: &str| {
            let mut uuid = [0u8; UUID_LENGTH];
            let status = sv_database_add_group(
                database,
                std::ptr::null(),
                name.as_ptr(),
                name.len(),
                0,
                uuid.as_mut_ptr(),
            );
            assert_eq!(status, SV_OK);
            uuid
        };
        let parent = add("Parent");
        let child = add("Child");

        let mut changed = false;
        let renamed = "Renamed";
        for expected in [true, false] {
            assert_eq!(
                sv_database_rename_group(
                    database,
                    child.as_ptr(),
                    renamed.as_ptr(),
                    renamed.len(),
                    0,
                    &mut changed
                ),
                SV_OK
            );
            assert_eq!(changed, expected);
        }

        let mut moved = false;
        for expected in [true, false] {
            assert_eq!(
                sv_database_move_group(database, child.as_ptr(), parent.as_ptr(), 0, &mut moved),
                SV_OK
            );
            assert_eq!(moved, expected);
        }
        assert_eq!(
            sv_database_move_group(database, parent.as_ptr(), child.as_ptr(), 0, &mut moved),
            SV_INVALID_ARGUMENT
        );
        assert!(!moved);

        let mut list = std::ptr::null_mut();
        assert_eq!(
            sv_database_group(database, parent.as_ptr(), &mut list),
            SV_OK
        );
        assert_eq!(sv_list_length(list), 1);
        assert!(sv_list_is_group(list, 0));
        assert_eq!(list_text(list, 0, SV_COLUMN_TITLE), "Renamed");
        sv_list_free(list);
        sv_database_free(database);
    }
}

#[test]
fn reports_kdbx3_files_with_their_own_status() {
    const KDBX31: &[u8] = include_bytes!("../../tests/fixtures/kdbx31-aeskdf.kdbx");
    unsafe {
        let mut database = std::ptr::null_mut();
        let status = sv_database_open(
            KDBX31.as_ptr(),
            KDBX31.len(),
            PASSWORD.as_ptr(),
            PASSWORD.len(),
            true,
            std::ptr::null(),
            0,
            &mut database,
        );
        assert_eq!(status, SV_KDBX3_UNSUPPORTED);
        assert!(database.is_null());
    }
}

fn identifier(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    &text[..end]
}

fn number(text: &str) -> i64 {
    let digits: String = text
        .trim_start()
        .chars()
        .take_while(|c| *c == '-' || c.is_ascii_digit())
        .collect();
    digits.parse().unwrap()
}

/// `SV_NAME = value` in the header's enums.
fn header_constants(header: &str) -> BTreeMap<String, i64> {
    header
        .match_indices("SV_")
        .filter_map(|(start, _)| {
            let name = identifier(&header[start..]);
            let value = header[start + name.len()..]
                .trim_start()
                .strip_prefix('=')?;
            Some((name.to_owned(), number(value)))
        })
        .collect()
}

/// `pub const SV_NAME: type = value;` in the Rust sources.
fn rust_constants(rust: &str) -> BTreeMap<String, i64> {
    rust.match_indices("pub const SV_")
        .filter_map(|(start, _)| {
            let declaration = &rust[start + "pub const ".len()..];
            let (_, value) = declaration.split_once('=')?;
            Some((identifier(declaration).to_owned(), number(value)))
        })
        .collect()
}

/// Names of `sv_` functions declared or defined right after one of
/// `preceding`.
fn functions(source: &str, preceding: &[&str]) -> BTreeSet<String> {
    source
        .match_indices("sv_")
        .filter_map(|(start, _)| {
            let name = identifier(&source[start..]);
            let declared = preceding.iter().any(|p| source[..start].ends_with(p))
                && source[start + name.len()..].starts_with('(');
            declared.then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn header_and_rust_declare_the_same_constants_and_functions() {
    let header = include_str!("../../include/sailvault_core.h");
    let rust = [
        include_str!("mod.rs"),
        include_str!("bitwarden.rs"),
        include_str!("database.rs"),
        include_str!("edit.rs"),
        include_str!("password.rs"),
        include_str!("read.rs"),
    ]
    .concat();
    let constants = header_constants(header);
    assert!(constants.len() > 25);
    assert_eq!(constants, rust_constants(&rust));
    let declared = functions(header, &[" ", "*"]);
    assert!(declared.len() > 35);
    assert_eq!(declared, functions(&rust, &["fn "]));
}
