//! New databases, laid out like the ones KeePassXC's new-database wizard
//! creates (`NewDatabaseWizard.cpp`, `Metadata::init`,
//! `KdbxXmlWriter::writeMetadata`).

use super::database::{encode_uuid, Database};
use super::edit::{
    build_group, element, kdbx_time, new_uuid, text, DEFAULT_HISTORY_MAX_ITEMS,
    DEFAULT_HISTORY_MAX_SIZE, GROUP_ICON, NO_UUID,
};
use super::error::{KdbxError, Result};
use super::header::{Cipher, Compression, OuterHeader};
use super::inner_header::InnerHeader;
use super::kdf::{Argon2Variant, KdfParameters, ARGON2_VERSION_13};
use super::key::CompositeKey;
use super::xml::Element;

// KeePassXC tunes Argon2d to one second on the creating machine. SailVault
// uses Argon2id, which RFC 9106 recommends, with fixed parameters measured
// on the Jolla Phone: about 60 ms per iteration per 64 MiB, so these take
// about 0.9 s there and far less on a PC. Four lanes let KeePassXC use four
// threads.
const ARGON2_ITERATIONS: u64 = 3;
const ARGON2_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const ARGON2_PARALLELISM: u32 = 4;
const MAINTENANCE_HISTORY_DAYS: &str = "365";
const ROOT_GROUP_NAME: &str = "Root";

impl Database {
    /// A new, empty database named `name`, protected by `key`: KDBX 4.0,
    /// AES-256, gzip and Argon2id, with the metadata and root group a new
    /// KeePassXC database has. It exists in memory until it is saved.
    pub fn create(key: CompositeKey, name: &str, now: i64) -> Result<Self> {
        if name.is_empty() {
            return Err(KdbxError::InvalidGroup("empty name"));
        }
        let kdf = KdfParameters::Argon2 {
            variant: Argon2Variant::Argon2id,
            iterations: ARGON2_ITERATIONS,
            memory_bytes: ARGON2_MEMORY_BYTES,
            parallelism: ARGON2_PARALLELISM,
            version: ARGON2_VERSION_13,
            salt: Vec::new(),
        };
        let header = OuterHeader::new(Cipher::Aes256, Compression::Gzip, kdf)?;
        let time = kdbx_time(now);
        let root = build_group(&new_uuid()?, ROOT_GROUP_NAME, GROUP_ICON, "null", &time);
        let document = element(
            "KeePassFile",
            vec![
                metadata(name, &time),
                element("Root", vec![root, element("DeletedObjects", Vec::new())]),
            ],
        );
        Database::from_parts(header, InnerHeader::default(), document, key)
    }
}

fn metadata(name: &str, time: &str) -> Element {
    let no_uuid = encode_uuid(&NO_UUID);
    element(
        "Meta",
        vec![
            text("Generator", "SailVault"),
            text("DatabaseName", name),
            text("DatabaseNameChanged", time),
            text("DatabaseDescription", ""),
            text("DatabaseDescriptionChanged", time),
            text("DefaultUserName", ""),
            text("DefaultUserNameChanged", time),
            text("MaintenanceHistoryDays", MAINTENANCE_HISTORY_DAYS),
            text("Color", ""),
            text("MasterKeyChanged", time),
            text("MasterKeyChangeRec", "-1"),
            text("MasterKeyChangeForce", "-1"),
            element(
                "MemoryProtection",
                vec![
                    text("ProtectTitle", "False"),
                    text("ProtectUserName", "False"),
                    text("ProtectPassword", "True"),
                    text("ProtectURL", "False"),
                    text("ProtectNotes", "False"),
                ],
            ),
            element("CustomIcons", Vec::new()),
            text("RecycleBinEnabled", "True"),
            text("RecycleBinUUID", &no_uuid),
            text("RecycleBinChanged", time),
            text("EntryTemplatesGroup", &no_uuid),
            text("EntryTemplatesGroupChanged", time),
            text("LastSelectedGroup", &no_uuid),
            text("LastTopVisibleGroup", &no_uuid),
            text("HistoryMaxItems", &DEFAULT_HISTORY_MAX_ITEMS.to_string()),
            text("HistoryMaxSize", &DEFAULT_HISTORY_MAX_SIZE.to_string()),
            text("SettingsChanged", time),
        ],
    )
}
