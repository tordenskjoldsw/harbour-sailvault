use std::fmt;

/// Errors never carry key material or database content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxError {
    NotKdbx,
    /// KDBX 3.x is detected but not read; the UI asks the user to convert
    /// the database to KDBX 4 in KeePassXC.
    Kdbx3Unsupported,
    UnsupportedVersion {
        major: u16,
        minor: u16,
    },
    InvalidHeader(&'static str),
    UnsupportedCipher,
    UnsupportedCompression,
    UnsupportedKdf,
    KdfParametersOutOfRange,
    InvalidKeyFile,
    /// The header HMAC does not match: wrong password or key file.
    InvalidCredentials,
    HeaderCorrupted,
    PayloadCorrupted,
    DecryptionFailed,
    DecompressionFailed,
    InvalidInnerHeader(&'static str),
    InvalidXml(&'static str),
    LimitExceeded(&'static str),
    CompressionFailed,
    /// The kernel provided no random bytes; nothing was written.
    RandomUnavailable,
    /// The serialized database did not decrypt back to the same content;
    /// nothing is written.
    WriteVerificationFailed,
    InvalidEntry(&'static str),
    UnknownGroup,
    UnknownEntry,
    RootGroupProtected,
}

impl fmt::Display for KdbxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotKdbx => f.write_str("not a KeePass database"),
            Self::Kdbx3Unsupported => f.write_str("KDBX 3 databases are not supported"),
            Self::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported KDBX version {major}.{minor}")
            }
            Self::InvalidHeader(reason) => write!(f, "invalid header: {reason}"),
            Self::UnsupportedCipher => f.write_str("unsupported cipher"),
            Self::UnsupportedCompression => f.write_str("unsupported compression"),
            Self::UnsupportedKdf => f.write_str("unsupported key derivation function"),
            Self::KdfParametersOutOfRange => {
                f.write_str("key derivation parameters are outside the accepted range")
            }
            Self::InvalidKeyFile => f.write_str("invalid key file"),
            Self::InvalidCredentials => f.write_str("wrong password or key file"),
            Self::HeaderCorrupted => f.write_str("header is corrupted"),
            Self::PayloadCorrupted => f.write_str("database content is corrupted"),
            Self::DecryptionFailed => f.write_str("decryption failed"),
            Self::DecompressionFailed => f.write_str("decompression failed"),
            Self::InvalidInnerHeader(reason) => write!(f, "invalid inner header: {reason}"),
            Self::InvalidXml(reason) => write!(f, "invalid database XML: {reason}"),
            Self::LimitExceeded(what) => write!(f, "limit exceeded: {what}"),
            Self::CompressionFailed => f.write_str("compression failed"),
            Self::RandomUnavailable => f.write_str("random number generator unavailable"),
            Self::WriteVerificationFailed => {
                f.write_str("the written database does not decrypt to the same content")
            }
            Self::InvalidEntry(reason) => write!(f, "invalid entry: {reason}"),
            Self::UnknownGroup => f.write_str("group not found"),
            Self::UnknownEntry => f.write_str("entry not found"),
            Self::RootGroupProtected => f.write_str("the root group cannot be deleted"),
        }
    }
}

impl std::error::Error for KdbxError {}

impl From<getrandom::Error> for KdbxError {
    fn from(_: getrandom::Error) -> Self {
        Self::RandomUnavailable
    }
}

pub type Result<T> = std::result::Result<T, KdbxError>;
