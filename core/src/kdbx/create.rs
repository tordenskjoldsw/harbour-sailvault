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

// Four lanes let KeePassXC use four threads; the core runs them in turn.
const ARGON2_PARALLELISM: u32 = 4;
const MIB: u64 = 1024 * 1024;
const MAINTENANCE_HISTORY_DAYS: &str = "365";
const ROOT_GROUP_NAME: &str = "Root";

/// How much work the key derivation of a new database costs. KeePassXC tunes
/// Argon2d to one second on the creating machine; SailVault uses Argon2id,
/// which RFC 9106 recommends, with fixed parameters. Measured on the Jolla
/// Phone (2026-10-03, median of three runs): Standard 0.96 s, High 2.45 s,
/// Maximum 4.92 s, for every unlock and save. Even Standard has four times
/// the memory of RFC 9106's 64 MiB option and of Bitwarden's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfLevel {
    Standard,
    High,
    Maximum,
}

impl KdfLevel {
    fn parameters(self) -> KdfParameters {
        let (iterations, memory_bytes) = match self {
            Self::Standard => (3, 256 * MIB),
            Self::High => (4, 512 * MIB),
            // The KDBX reader accepts at most 1 GiB.
            Self::Maximum => (4, 1024 * MIB),
        };
        KdfParameters::Argon2 {
            variant: Argon2Variant::Argon2id,
            iterations,
            memory_bytes,
            parallelism: ARGON2_PARALLELISM,
            version: ARGON2_VERSION_13,
            salt: Vec::new(),
        }
    }
}

impl Database {
    /// A new, empty database named `name`, protected by `key`: KDBX 4.0,
    /// AES-256, gzip and Argon2id at `level`, with the metadata and root
    /// group a new KeePassXC database has. It exists in memory until it is
    /// saved.
    pub fn create(key: CompositeKey, name: &str, level: KdfLevel, now: i64) -> Result<Self> {
        if name.is_empty() {
            return Err(KdbxError::InvalidGroup("empty name"));
        }
        let kdf = level.parameters();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_level_saves_a_file_that_opens_again() {
        let key = || CompositeKey::new(Some(b"level test passphrase"), None).unwrap();
        for (level, memory_bytes) in [
            (KdfLevel::Standard, 256 * MIB),
            (KdfLevel::High, 512 * MIB),
            (KdfLevel::Maximum, 1024 * MIB),
        ] {
            let database = Database::create(key(), "Passwords", level, 0).unwrap();
            let saved = database.save().unwrap();
            let reopened = Database::open(&saved, key()).unwrap();
            assert!(
                matches!(
                    reopened.header().kdf,
                    KdfParameters::Argon2 { memory_bytes: m, .. } if m == memory_bytes
                ),
                "{level:?}"
            );
        }
    }
}
