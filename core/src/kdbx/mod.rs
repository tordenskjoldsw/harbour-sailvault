//! KDBX 4 reader and writer. Format details are verified against KeePassXC
//! (`src/format/Kdbx4Reader.cpp`, `Kdbx4Writer.cpp`, `KdbxXmlReader.cpp`,
//! `KdbxXmlWriter.cpp`, `keys/`).

mod database;
mod edit;
mod error;
mod header;
mod inner_header;
mod kdf;
mod key;
mod payload;
mod reader;
mod search;
mod variant_dictionary;
mod xml;

pub use database::{Attachment, Database, DeletedObject, Entry, Field, Group};
pub use edit::{NewEntry, NewField, NewGroup};
pub use error::{KdbxError, Result};
pub use header::{Cipher, Compression, OuterHeader};
pub use inner_header::Binary;
pub use kdf::{Argon2Variant, KdfParameters};
pub use key::CompositeKey;
pub use search::ListedEntry;
pub use variant_dictionary::{Value, VariantDictionary};
pub use xml::{Element, Node};
