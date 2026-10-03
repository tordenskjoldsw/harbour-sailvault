use std::fmt;

/// Errors never carry key material or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKdfParameters,
    InvalidEncString,
    UnsupportedEncStringType(u8),
    WrongKeyType,
    MacMismatch,
    DecryptionFailed,
    InvalidKey,
    UnsupportedKeyFormat,
    InvalidUtf8,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKdfParameters => {
                f.write_str("KDF parameters are outside the accepted range")
            }
            Self::InvalidEncString => f.write_str("malformed encrypted string"),
            Self::UnsupportedEncStringType(enc_type) => {
                write!(f, "unsupported encrypted string type {enc_type}")
            }
            Self::WrongKeyType => f.write_str("key type does not match the encrypted string type"),
            Self::MacMismatch => f.write_str("message authentication failed"),
            Self::DecryptionFailed => f.write_str("decryption failed"),
            Self::InvalidKey => f.write_str("invalid key"),
            Self::UnsupportedKeyFormat => f.write_str("unsupported key format"),
            Self::InvalidUtf8 => f.write_str("decrypted data is not valid UTF-8"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;
