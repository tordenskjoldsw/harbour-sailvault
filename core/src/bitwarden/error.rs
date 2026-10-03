use std::fmt;

/// Errors never carry key material or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    InvalidKdfParameters,
    InvalidEncString,
    UnsupportedEncStringType(u8),
    MacMismatch,
    DecryptionFailed,
    InvalidUtf8,
    /// The file is not a Bitwarden/Vaultwarden JSON export.
    NotAnExport,
    /// The decrypted content of a password-protected export is not valid.
    InvalidJson,
    TooLarge,
    /// Encrypted with the account key; only the server can decrypt it.
    AccountRestricted,
    PasswordRequired,
    WrongPassword,
    /// A folder path is nested deeper than SailVault imports.
    FolderTooDeep,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKdfParameters => {
                f.write_str("KDF parameters are outside the accepted range")
            }
            Self::InvalidEncString => f.write_str("malformed encrypted string"),
            Self::UnsupportedEncStringType(enc_type) => {
                write!(f, "unsupported encrypted string type {enc_type}")
            }
            Self::MacMismatch => f.write_str("wrong password or corrupted export"),
            Self::DecryptionFailed => f.write_str("decryption failed"),
            Self::InvalidUtf8 => f.write_str("decrypted data is not valid UTF-8"),
            Self::NotAnExport => f.write_str("not a Bitwarden JSON export"),
            Self::InvalidJson => f.write_str("the export content is not valid"),
            Self::TooLarge => f.write_str("the export is too large"),
            Self::AccountRestricted => {
                f.write_str("account-restricted exports cannot be decrypted offline")
            }
            Self::PasswordRequired => f.write_str("the export needs its password"),
            Self::WrongPassword => f.write_str("wrong export password"),
            Self::FolderTooDeep => f.write_str("a folder is nested too deeply"),
        }
    }
}

impl std::error::Error for ImportError {}

pub type Result<T> = std::result::Result<T, ImportError>;
