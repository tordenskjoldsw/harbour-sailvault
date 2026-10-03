//! Reading Bitwarden/Vaultwarden JSON exports, unencrypted or
//! password-protected. Format details and their sources:
//! `docs/bitwarden-export.md`.

mod base64;
mod enc_string;
mod error;
mod export;
mod import;
mod kdf;
mod keys;

pub use enc_string::EncString;
pub use error::{ImportError, Result};
pub use export::{
    export_kind, read_export, ExportKind, Field, Folder, Item, Login, Passkey, PasswordHistoryItem,
    Section, Text, Uri, Vault, MAX_EXPORT_SIZE,
};
pub use import::import_group;
pub use kdf::Kdf;
pub use keys::SymmetricKey;
