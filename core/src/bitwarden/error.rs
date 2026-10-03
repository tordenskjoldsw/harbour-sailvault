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
        }
    }
}

impl std::error::Error for ImportError {}

pub type Result<T> = std::result::Result<T, ImportError>;
