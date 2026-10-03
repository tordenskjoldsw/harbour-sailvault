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

fn open(data: &[u8], key_file: bool) -> Database {
    let key = CompositeKey::new(Some(PASSWORD), key_file.then_some(KEY_FILE)).unwrap();
    Database::open(data, &key).unwrap()
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
    let wrong = CompositeKey::new(Some(b"wrong"), None).unwrap();
    for data in [AES_AESKDF, AES_ARGON2D, CHACHA20_ARGON2ID, TWOFISH_AESKDF] {
        assert_eq!(
            Database::open(data, &wrong).map(|_| ()),
            Err(KdbxError::InvalidCredentials)
        );
    }
    let without_key_file = CompositeKey::new(Some(PASSWORD), None).unwrap();
    assert_eq!(
        Database::open(AES_AESKDF_KEYFILE, &without_key_file).map(|_| ()),
        Err(KdbxError::InvalidCredentials)
    );
}

#[test]
fn tampered_files_are_rejected() {
    let key = CompositeKey::new(Some(PASSWORD), None).unwrap();
    let (_, header_length) = OuterHeader::parse(AES_ARGON2D).unwrap();

    let mut header = AES_ARGON2D.to_vec();
    header[header_length - 10] ^= 0x01;
    assert!(Database::open(&header, &key).is_err());

    let mut payload = AES_ARGON2D.to_vec();
    let last = payload.len() - 50;
    payload[last] ^= 0x01;
    assert_eq!(
        Database::open(&payload, &key).map(|_| ()),
        Err(KdbxError::PayloadCorrupted)
    );

    let truncated = &AES_ARGON2D[..AES_ARGON2D.len() - 40];
    assert_eq!(
        Database::open(truncated, &key).map(|_| ()),
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
