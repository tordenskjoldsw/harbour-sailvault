//! Reads databases written by KeePassXC (`core/tests/fixtures/README.md`).

use sailvault_core::kdbx::{
    Argon2Variant, Cipher, Compression, KdbxError, KdfParameters, OuterHeader,
};

const KDBX31: &[u8] = include_bytes!("fixtures/kdbx31-aeskdf.kdbx");
const KDBX31_KEYFILE: &[u8] = include_bytes!("fixtures/kdbx31-aeskdf-keyfile.kdbx");
const AES_AESKDF: &[u8] = include_bytes!("fixtures/kdbx4-aes-aeskdf.kdbx");
const AES_AESKDF_KEYFILE: &[u8] = include_bytes!("fixtures/kdbx4-aes-aeskdf-keyfile.kdbx");
const AES_ARGON2D: &[u8] = include_bytes!("fixtures/kdbx4-aes-argon2d.kdbx");
const CHACHA20_ARGON2ID: &[u8] = include_bytes!("fixtures/kdbx4-chacha20-argon2id.kdbx");
const TWOFISH_AESKDF: &[u8] = include_bytes!("fixtures/kdbx4-twofish-aeskdf.kdbx");

#[derive(Debug, PartialEq)]
enum Kdf {
    Aes,
    Argon2d,
    Argon2id,
}

fn header(data: &[u8]) -> OuterHeader {
    OuterHeader::parse(data).unwrap().0
}

fn kdf(header: &OuterHeader) -> Kdf {
    match &header.kdf {
        KdfParameters::AesKdf { .. } => Kdf::Aes,
        KdfParameters::Argon2 {
            variant: Argon2Variant::Argon2d,
            ..
        } => Kdf::Argon2d,
        KdfParameters::Argon2 {
            variant: Argon2Variant::Argon2id,
            ..
        } => Kdf::Argon2id,
    }
}

#[test]
fn fixture_headers_match_the_documented_settings() {
    let expected = [
        (AES_AESKDF, Cipher::Aes256, Kdf::Aes),
        (AES_AESKDF_KEYFILE, Cipher::Aes256, Kdf::Aes),
        (AES_ARGON2D, Cipher::Aes256, Kdf::Argon2d),
        (CHACHA20_ARGON2ID, Cipher::ChaCha20, Kdf::Argon2id),
        (TWOFISH_AESKDF, Cipher::Twofish, Kdf::Aes),
    ];
    for (data, cipher, expected_kdf) in expected {
        let header = header(data);
        assert_eq!(header.minor_version, 0);
        assert_eq!(header.cipher, cipher);
        assert_eq!(header.compression, Compression::Gzip);
        assert_eq!(kdf(&header), expected_kdf);
    }
}

#[test]
fn gui_fixtures_use_the_documented_kdf_parameters() {
    for data in [AES_ARGON2D, CHACHA20_ARGON2ID] {
        match header(data).kdf {
            KdfParameters::Argon2 {
                iterations,
                memory_bytes,
                parallelism,
                version,
                ..
            } => {
                assert_eq!((iterations, memory_bytes, parallelism), (2, 8 << 20, 2));
                assert_eq!(version, 0x13);
            }
            other => panic!("unexpected KDF {other:?}"),
        }
    }
    match header(TWOFISH_AESKDF).kdf {
        KdfParameters::AesKdf { rounds, .. } => assert_eq!(rounds, 10_000),
        other => panic!("unexpected KDF {other:?}"),
    }
}

#[test]
fn kdbx3_is_detected_and_reported() {
    for data in [KDBX31, KDBX31_KEYFILE] {
        assert_eq!(
            OuterHeader::parse(data).map(|_| ()),
            Err(KdbxError::Kdbx3Unsupported)
        );
    }
}

#[test]
fn non_kdbx_and_truncated_input_is_rejected() {
    assert_eq!(
        OuterHeader::parse(b"not a database").map(|_| ()),
        Err(KdbxError::NotKdbx)
    );
    assert_eq!(OuterHeader::parse(&[]).map(|_| ()), Err(KdbxError::NotKdbx));
    for length in [12, 40, 100] {
        assert!(matches!(
            OuterHeader::parse(&AES_ARGON2D[..length]),
            Err(KdbxError::InvalidHeader(_))
        ));
    }
}

#[test]
fn newer_major_version_is_rejected() {
    let mut data = AES_ARGON2D.to_vec();
    data[10] = 5;
    assert_eq!(
        OuterHeader::parse(&data).map(|_| ()),
        Err(KdbxError::UnsupportedVersion { major: 5, minor: 0 })
    );
}

const PASSWORD: &[u8] = b"sailvault-fixture";
const KEY_FILE: &[u8] = include_bytes!("fixtures/fixture.keyx");

use sailvault_core::kdbx::{CompositeKey, Database, Entry, Group};

fn key(key_file: bool) -> CompositeKey {
    CompositeKey::new(Some(PASSWORD), key_file.then_some(KEY_FILE)).unwrap()
}

fn open(data: &[u8], key_file: bool) -> Database {
    Database::open(data, key(key_file)).unwrap()
}

fn kdbx4_fixtures() -> [(&'static str, Database); 5] {
    [
        ("aes-aeskdf", open(AES_AESKDF, false)),
        ("aes-aeskdf-keyfile", open(AES_AESKDF_KEYFILE, true)),
        ("aes-argon2d", open(AES_ARGON2D, false)),
        ("chacha20-argon2id", open(CHACHA20_ARGON2ID, false)),
        ("twofish-aeskdf", open(TWOFISH_AESKDF, false)),
    ]
}

fn uuid(base64: &str) -> [u8; 16] {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(base64)
        .unwrap()
        .try_into()
        .unwrap()
}

fn value(entry: &Entry<'_>, key: &str) -> String {
    entry.field(key).unwrap().value().to_string()
}

fn subgroup<'a>(group: &Group<'a>, name: &str) -> Group<'a> {
    group.groups().find(|g| *g.name() == name).unwrap()
}

fn entry<'a>(group: &Group<'a>, title: &str) -> Entry<'a> {
    group
        .entries()
        .find(|e| value(e, "Title") == title)
        .unwrap_or_else(|| panic!("entry {title} missing"))
}

#[test]
fn every_kdbx4_fixture_exposes_the_full_content() {
    for (name, database) in kdbx4_fixtures() {
        let root = database.root_group().unwrap();
        assert_eq!(*root.name(), "Root", "{name}");

        let login = entry(&root, "Example login");
        assert_eq!(
            login.uuid(),
            Some(uuid("EBAQEBAQEBAQEBAQEBAQEA==")),
            "{name}"
        );
        assert_eq!(value(&login, "UserName"), "alice@example.org");
        assert_eq!(value(&login, "Password"), "current-password-3");
        assert!(login.field("Password").unwrap().is_protected());
        assert_eq!(value(&login, "PIN"), "4711");
        assert!(login.field("PIN").unwrap().is_protected());
        assert_eq!(value(&login, "Department"), "Engineering");
        assert!(!login.field("Department").unwrap().is_protected());
        assert_eq!(value(&login, "KP2A_URL_1"), "https://login.example.org");
        assert_eq!(
            value(&login, "Notes"),
            "First line\nSecond line with umlauts: äöü ß"
        );
        assert_eq!(
            value(&login, "otp"),
            "otpauth://totp/Example:alice%40example.org?secret=JBSWY3DPEHPK3PXP\
             &period=30&digits=6&issuer=Example"
        );
        let mut tags: Vec<String> = login.tags().split([',', ';']).map(String::from).collect();
        tags.sort();
        assert_eq!(tags, ["favorite", "work"], "{name}");

        let history: Vec<String> = login.history().map(|h| value(&h, "Password")).collect();
        assert_eq!(history, ["old-password-1", "old-password-2"], "{name}");

        let special = entry(&root, "Special characters äöü 🔐");
        assert_eq!(
            value(&special, "Password"),
            "<special> & \"quotes\" 'apostrophes' äöü 🔐"
        );
        let attachments: Vec<_> = special.attachments().collect();
        assert_eq!(attachments.len(), 1, "{name}");
        assert_eq!(*attachments[0].name(), "hello.txt");
        let binary = database.attachment(&attachments[0]).unwrap();
        assert_eq!(
            binary.data.as_slice(),
            b"Hello from a SailVault test attachment.\n"
        );

        let cards = subgroup(&subgroup(&root, "Banking"), "Cards");
        let card = entry(&cards, "Example card");
        assert_eq!(value(&card, "card_number"), "4111111111111111");
        assert_eq!(value(&card, "card_code"), "123");
        assert_eq!(value(&card, "Password"), "");

        let recycle_bin = subgroup(&root, "Recycle Bin");
        assert_eq!(database.recycle_bin(), recycle_bin.uuid(), "{name}");
        assert_eq!(
            value(&entry(&recycle_bin, "Recycled entry"), "Password"),
            "recycled-password"
        );

        let deleted = database.deleted_objects();
        assert_eq!(deleted.len(), 1, "{name}");
        assert_eq!(deleted[0].uuid, uuid("cHBwcHBwcHBwcHBwcHBwcA=="));

        let meta = database.meta().unwrap();
        let custom_data: Vec<String> = meta
            .child("CustomData")
            .unwrap()
            .children_named("Item")
            .map(|item| item.child("Key").unwrap().text().to_string())
            .collect();
        assert!(
            custom_data.contains(&"SailVaultFixtureMeta".to_owned()),
            "{name}"
        );
        let entry_custom_data: Vec<String> = login
            .element()
            .child("CustomData")
            .unwrap()
            .children_named("Item")
            .map(|item| item.child("Key").unwrap().text().to_string())
            .collect();
        assert!(
            entry_custom_data.contains(&"SailVaultFixtureEntry".to_owned()),
            "{name}"
        );
    }
}

#[test]
fn wrong_password_or_missing_key_file_is_reported() {
    for data in [AES_AESKDF, AES_ARGON2D, CHACHA20_ARGON2ID, TWOFISH_AESKDF] {
        let wrong = CompositeKey::new(Some(b"wrong"), None).unwrap();
        assert_eq!(
            Database::open(data, wrong).map(|_| ()),
            Err(KdbxError::InvalidCredentials)
        );
    }
    assert_eq!(
        Database::open(AES_AESKDF_KEYFILE, key(false)).map(|_| ()),
        Err(KdbxError::InvalidCredentials)
    );
}

#[test]
fn tampered_files_are_rejected() {
    let (_, header_length) = OuterHeader::parse(AES_ARGON2D).unwrap();

    let mut hash = AES_ARGON2D.to_vec();
    hash[header_length] ^= 0x01;
    assert_eq!(
        Database::open(&hash, key(false)).map(|_| ()),
        Err(KdbxError::HeaderCorrupted)
    );

    let mut header = AES_ARGON2D.to_vec();
    header[header_length - 10] ^= 0x01;
    assert!(Database::open(&header, key(false)).is_err());

    let mut payload = AES_ARGON2D.to_vec();
    let last = payload.len() - 50;
    payload[last] ^= 0x01;
    assert_eq!(
        Database::open(&payload, key(false)).map(|_| ()),
        Err(KdbxError::PayloadCorrupted)
    );

    let truncated = &AES_ARGON2D[..AES_ARGON2D.len() - 40];
    assert_eq!(
        Database::open(truncated, key(false)).map(|_| ()),
        Err(KdbxError::PayloadCorrupted)
    );
}

fn titles(entries: &[sailvault_core::kdbx::ListedEntry<'_>]) -> Vec<String> {
    entries
        .iter()
        .map(|listed| value(&listed.entry, "Title"))
        .collect()
}

#[test]
fn lists_all_current_entries_with_their_group() {
    let database = open(AES_ARGON2D, false);
    let entries = database.entries().unwrap();
    assert_eq!(
        titles(&entries),
        [
            "Example login",
            "Special characters äöü 🔐",
            "Example card",
            "Recycled entry"
        ]
    );
    let groups: Vec<String> = entries.iter().map(|l| l.group.name().to_string()).collect();
    assert_eq!(groups, ["Root", "Root", "Cards", "Recycle Bin"]);
    let searchable: Vec<bool> = entries.iter().map(|l| l.searchable).collect();
    assert_eq!(searchable, [true, true, true, false]);
}

#[test]
fn search_matches_visible_fields_and_tags_but_not_secrets() {
    let database = open(AES_ARGON2D, false);
    let search = |query: &str| titles(&database.search(query).unwrap());

    assert_eq!(search("EXAMPLE login"), ["Example login"]);
    assert_eq!(search("alice"), ["Example login"]);
    assert_eq!(search("example.org"), ["Example login"]);
    assert_eq!(search("umlauts"), ["Example login"]);
    assert_eq!(search("favorite"), ["Example login"]);
    assert_eq!(
        search("ÄÖÜ"),
        ["Example login", "Special characters äöü 🔐"]
    );
    assert!(search("current-password-3").is_empty());
    assert!(search("4111111111111111").is_empty());
    assert!(search("recycled").is_empty());
    assert!(search("example nothing-matches").is_empty());
    assert_eq!(
        search("  "),
        ["Example login", "Special characters äöü 🔐", "Example card"]
    );
}

const LARGE: &[u8] = include_bytes!("fixtures/kdbx4-1000-entries.kdbx");

#[test]
fn large_fixture_lists_and_searches_1000_entries() {
    let database = open(LARGE, false);
    let entries = database.entries().unwrap();
    assert_eq!(entries.len(), 1000);
    assert_eq!(database.root_group().unwrap().groups().count(), 10);

    let with_history = entries
        .iter()
        .filter(|listed| listed.entry.history().count() == 2)
        .count();
    assert_eq!(with_history, 100);

    let found = database.search("user0500@example.org").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(value(&found[0].entry, "Password"), "password-0500");
    assert_eq!(database.search("example.org").unwrap().len(), 1000);
}

// Writer: every fixture must survive a save unchanged, and KeePassXC must
// read what SailVault writes.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct TempFile(PathBuf);

impl TempFile {
    fn write(name: &str, data: &[u8]) -> Self {
        let path =
            std::env::temp_dir().join(format!("sailvault-{}-{name}.kdbx", std::process::id()));
        std::fs::write(&path, data).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Runs keepassxc-cli, the reference implementation, on a database file:
/// `keepassxc-cli <arguments> -q [-k fixture.keyx] <file> <trailing>`.
fn keepassxc_cli(arguments: &[&str], file: &TempFile, key_file: bool, trailing: &[&str]) -> String {
    let mut command = Command::new("keepassxc-cli");
    // KeePassXC keeps CustomData in a QHash, whose order depends on the
    // per-process hash seed; a fixed seed makes two exports comparable.
    command.env("QT_HASH_SEED", "0").args(arguments).arg("-q");
    if key_file {
        command.arg("-k").arg(fixture_path("fixture.keyx"));
    }
    let mut child = command
        .arg(&file.0)
        .args(trailing)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli must be installed to run the writer tests");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"sailvault-fixture\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "keepassxc-cli {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// KeePassXC stamps every CustomData `_LAST_MODIFIED` item with the export
/// time, so those items cannot be compared between two exports.
fn without_export_time(xml: &str) -> String {
    let mut lines: Vec<&str> = xml.lines().collect();
    while let Some(key) = lines
        .iter()
        .position(|line| line.trim() == "<Key>_LAST_MODIFIED</Key>")
    {
        lines.drain(key - 1..key + 3);
    }
    lines.join("\n")
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn settings(header: &OuterHeader) -> (u16, Cipher, Compression, KdfParameters) {
    let mut kdf = header.kdf.clone();
    match &mut kdf {
        KdfParameters::AesKdf { seed, .. } => *seed = [0; 32],
        KdfParameters::Argon2 { salt, .. } => salt.clear(),
    }
    (header.minor_version, header.cipher, header.compression, kdf)
}

fn all_kdbx4_fixtures() -> Vec<(&'static str, &'static [u8], bool)> {
    vec![
        ("aes-aeskdf", AES_AESKDF, false),
        ("aes-aeskdf-keyfile", AES_AESKDF_KEYFILE, true),
        ("aes-argon2d", AES_ARGON2D, false),
        ("chacha20-argon2id", CHACHA20_ARGON2ID, false),
        ("twofish-aeskdf", TWOFISH_AESKDF, false),
        ("1000-entries", LARGE, false),
    ]
}

#[test]
fn saved_fixtures_reopen_with_identical_content_and_settings() {
    for (name, data, key_file) in all_kdbx4_fixtures() {
        let database = open(data, key_file);
        let saved = database.save().unwrap();
        assert_ne!(saved, data, "{name}: seeds must be fresh");

        let reopened = Database::open(&saved, key(key_file)).unwrap();
        assert!(reopened.document() == database.document(), "{name}");
        assert!(reopened.binaries() == database.binaries(), "{name}");
        assert_eq!(
            settings(reopened.header()),
            settings(database.header()),
            "{name}"
        );
        assert_ne!(
            reopened.header().kdf,
            database.header().kdf,
            "{name}: KDF seed must be fresh"
        );
    }
}

#[test]
fn keepassxc_reads_saved_fixtures_as_the_originals() {
    for (name, data, key_file) in all_kdbx4_fixtures() {
        let saved = open(data, key_file).save().unwrap();
        let original_file = TempFile::write(&format!("{name}-original"), data);
        let saved_file = TempFile::write(&format!("{name}-saved"), &saved);
        let original = without_export_time(&keepassxc_cli(
            &["export", "-f", "xml"],
            &original_file,
            key_file,
            &[],
        ));
        let exported = without_export_time(&keepassxc_cli(
            &["export", "-f", "xml"],
            &saved_file,
            key_file,
            &[],
        ));
        assert!(exported.contains("<KeePassFile>"), "{name}");
        let difference = original
            .lines()
            .zip(exported.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(line, (a, b))| format!("line {line}: {a:?} vs {b:?}"))
            .unwrap_or_else(|| {
                format!(
                    "{} vs {} lines",
                    original.lines().count(),
                    exported.lines().count()
                )
            });
        assert!(
            original == exported,
            "{name}: KeePassXC export differs at {difference}"
        );
    }
}

const NOW: i64 = 1_767_261_600; // 2026-01-01T10:00:00Z, the fixture timestamp

#[test]
fn added_entries_follow_keepassxc_layout_and_memory_protection() {
    let mut database = open(AES_ARGON2D, false);
    let root_uuid = database.root_group().unwrap().uuid().unwrap();
    let uuid = database
        .add_entry(
            &root_uuid,
            &[
                ("Title", "Added on the phone"),
                ("UserName", "bob"),
                ("Password", "p4ss <&>"),
                ("URL", "https://added.example.org"),
                ("Notes", "line one\nline two"),
                ("PIN", "0000"),
            ],
            NOW,
        )
        .unwrap();

    let root = database.root_group().unwrap();
    let added = root
        .entries()
        .find(|entry| entry.uuid() == Some(uuid))
        .expect("entry is in the root group");
    let keys: Vec<String> = added.fields().map(|f| f.key().to_string()).collect();
    assert_eq!(
        keys,
        ["Title", "UserName", "Password", "URL", "Notes", "PIN"]
    );
    assert_eq!(value(&added, "Title"), "Added on the phone");
    assert_eq!(value(&added, "Password"), "p4ss <&>");
    assert_eq!(value(&added, "Notes"), "line one\nline two");
    assert!(added.field("Password").unwrap().is_protected());
    assert!(!added.field("Title").unwrap().is_protected());
    assert!(!added.field("PIN").unwrap().is_protected());
    assert_eq!(added.history().count(), 0);

    let times = added.element().child("Times").unwrap();
    let fixture_time = root
        .element()
        .child("Times")
        .unwrap()
        .child("CreationTime")
        .unwrap()
        .text();
    for name in ["CreationTime", "LastModificationTime", "LocationChanged"] {
        assert_eq!(*times.child(name).unwrap().text(), *fixture_time, "{name}");
    }

    let children: Vec<&str> = root
        .element()
        .elements()
        .map(|element| element.name.as_str())
        .collect();
    let last_entry = children.iter().rposition(|name| *name == "Entry").unwrap();
    let first_group = children.iter().position(|name| *name == "Group").unwrap();
    assert!(last_entry < first_group, "entries stay before subgroups");
    assert_eq!(root.entries().last().unwrap().uuid(), Some(uuid));
}

#[test]
fn added_entry_in_a_subgroup_survives_a_save_and_keepassxc_reads_it() {
    let mut database = open(CHACHA20_ARGON2ID, false);
    let cards = subgroup(
        &subgroup(&database.root_group().unwrap(), "Banking"),
        "Cards",
    )
    .uuid()
    .unwrap();
    assert_eq!(
        database
            .add_entry(&[0xAB; 16], &[("Title", "x")], NOW)
            .map(|_| ()),
        Err(KdbxError::UnknownGroup)
    );
    database
        .add_entry(
            &cards,
            &[("Title", "Phone card"), ("Password", "s3cret äöü")],
            NOW,
        )
        .unwrap();

    let saved = database.save().unwrap();
    let reopened = Database::open(&saved, key(false)).unwrap();
    let cards = subgroup(
        &subgroup(&reopened.root_group().unwrap(), "Banking"),
        "Cards",
    );
    assert_eq!(
        value(&entry(&cards, "Phone card"), "Password"),
        "s3cret äöü"
    );
    assert_eq!(reopened.entries().unwrap().len(), 5);

    let file = TempFile::write("added-entry", &saved);
    let shown = keepassxc_cli(
        &["show", "-a", "Password", "-a", "UserName", "-a", "Title"],
        &file,
        false,
        &["Banking/Cards/Phone card"],
    );
    assert_eq!(shown, "s3cret äöü\n\nPhone card\n");
}

#[test]
fn edited_and_deleted_entries_survive_a_save_and_keepassxc_reads_them() {
    let mut database = open(AES_AESKDF, false);
    let (login, card, recycled) = {
        let root = database.root_group().unwrap();
        (
            entry(&root, "Example login").uuid().unwrap(),
            entry(
                &subgroup(&subgroup(&root, "Banking"), "Cards"),
                "Example card",
            )
            .uuid()
            .unwrap(),
            entry(&subgroup(&root, "Recycle Bin"), "Recycled entry")
                .uuid()
                .unwrap(),
        )
    };
    assert_eq!(
        database.update_entry(&login, &[("Password", "rotated-password-4")], NOW),
        Ok(true)
    );
    assert_eq!(database.delete_entry(&card, NOW), Ok(false));
    assert_eq!(database.delete_entry(&recycled, NOW), Ok(true));

    let saved = database.save().unwrap();
    let reopened = Database::open(&saved, key(false)).unwrap();
    let root = reopened.root_group().unwrap();
    let login = entry(&root, "Example login");
    assert_eq!(value(&login, "Password"), "rotated-password-4");
    let history: Vec<String> = login.history().map(|h| value(&h, "Password")).collect();
    assert_eq!(
        history,
        ["old-password-1", "old-password-2", "current-password-3"]
    );
    assert_eq!(
        subgroup(&subgroup(&root, "Banking"), "Cards")
            .entries()
            .count(),
        0
    );
    let bin = subgroup(&root, "Recycle Bin");
    assert_eq!(bin.entries().count(), 1);
    assert_eq!(
        value(&entry(&bin, "Example card"), "card_number"),
        "4111111111111111"
    );
    let deleted = reopened.deleted_objects();
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[1].uuid, recycled);

    let file = TempFile::write("edited", &saved);
    let listing = keepassxc_cli(&["ls", "-R", "-f"], &file, false, &[]);
    assert!(listing.contains("Recycle Bin/Example card\n"), "{listing}");
    assert!(!listing.contains("Recycled entry"), "{listing}");
    assert!(!listing.contains("Banking/Cards/Example card"), "{listing}");
    let shown = keepassxc_cli(
        &["show", "-a", "Password"],
        &file,
        false,
        &["Example login"],
    );
    assert_eq!(shown, "rotated-password-4\n");
}
