//! KDBX 4 reader and writer, and a KDBX 3 reader that converts to KDBX 4
//! (`kdbx3`). Format details are verified against KeePassXC
//! (`src/format/Kdbx4Reader.cpp`, `Kdbx4Writer.cpp`, `KdbxXmlReader.cpp`,
//! `KdbxXmlWriter.cpp`, `keys/`).

mod create;
mod database;
mod edit;
mod error;
mod header;
mod inner_header;
mod kdbx3;
mod kdf;
mod key;
mod layout;
mod merge;
mod merge_database;
mod payload;
mod reader;
mod search;
mod sync_settings;
mod time;
mod tree;
mod variant_dictionary;
mod xml;

pub use create::KdfLevel;
pub use database::{Attachment, Database, DeletedObject, Entry, Field, Group};
pub use error::{KdbxError, Result};
pub use header::{version, Cipher, Compression, OuterHeader};
pub use inner_header::Binary;
pub use kdf::{Argon2Variant, KdfParameters};
pub use key::CompositeKey;
pub use layout::{NewEntry, NewField, ORIGIN_BITWARDEN, STANDARD_KEYS};
pub use merge::{MergeSummary, NewGroup};
pub use merge_database::MergeChanges;
pub use search::ListedEntry;
pub use sync_settings::{SyncSettings, SYNC_TITLE};
pub use xml::{Element, Node};
