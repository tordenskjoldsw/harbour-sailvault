//! Bitwarden-compatible key derivation and decryption.
//! Protocol details and their sources: `docs/protocol.md`.

mod base64;
mod enc_string;
mod error;
mod kdf;
mod keys;

pub use enc_string::EncString;
pub use error::{CryptoError, Result};
pub use kdf::{normalize_email, Kdf, MasterKey};
pub use keys::SymmetricKey;
