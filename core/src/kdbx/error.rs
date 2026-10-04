use std::fmt;

/// Errors never carry key material or database content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxError {
    NotKdbx,
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
    /// Wrong password or key file: the KDBX 4 header HMAC or the KDBX 3
    /// start bytes do not match.
    InvalidCredentials,
    HeaderCorrupted,
    PayloadCorrupted,
    DecryptionFailed,
    DecompressionFailed,
    InvalidInnerHeader(&'static str),
    InvalidXml(&'static str),
    LimitExceeded(&'static str),
    CompressionFailed,
    EncryptionFailed,
    /// The kernel provided no random bytes; nothing was written.
    RandomUnavailable,
    /// The serialized database did not decrypt back to the same content;
    /// nothing is written.
    WriteVerificationFailed,
    InvalidEntry(&'static str),
    InvalidGroup(&'static str),
    UnknownGroup,
    UnknownEntry,
    RootGroupProtected,
    NotInRecycleBin,
}

impl fmt::Display for KdbxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotKdbx => f.write_str("not a KeePass database"),
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
            Self::EncryptionFailed => f.write_str("encryption failed"),
            Self::RandomUnavailable => f.write_str("random number generator unavailable"),
            Self::WriteVerificationFailed => {
                f.write_str("the written database does not decrypt to the same content")
            }
            Self::InvalidEntry(reason) => write!(f, "invalid entry: {reason}"),
            Self::InvalidGroup(reason) => write!(f, "invalid group: {reason}"),
            Self::UnknownGroup => f.write_str("group not found"),
            Self::UnknownEntry => f.write_str("entry not found"),
            Self::RootGroupProtected => f.write_str("the root group cannot be deleted or moved"),
            Self::NotInRecycleBin => f.write_str("the item is not in the recycle bin"),
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
