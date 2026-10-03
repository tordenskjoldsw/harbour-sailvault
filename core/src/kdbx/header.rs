use super::error::{KdbxError, Result};
use super::kdf::KdfParameters;
use super::reader::ByteReader;
use super::variant_dictionary::VariantDictionary;

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2_KDBX: u32 = 0xB54B_FB67;
const SUPPORTED_MINOR_VERSIONS: [u16; 2] = [0, 1];
const MAX_HEADER_LENGTH: usize = 1 << 20;

const FIELD_END: u8 = 0;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_COMPRESSION: u8 = 3;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_ENCRYPTION_IV: u8 = 7;
const FIELD_KDF_PARAMETERS: u8 = 11;
const FIELD_PUBLIC_CUSTOM_DATA: u8 = 12;

const CIPHER_AES256: [u8; 16] = uuid(0x31c1f2e6_bf714350_be580521_6afc5aff);
const CIPHER_CHACHA20: [u8; 16] = uuid(0xd6038a2b_8b6f4cb5_a524339a_31dbb59a);
const CIPHER_TWOFISH: [u8; 16] = uuid(0xad68f29f_576f4bb9_a36ad47a_f965346c);

pub(crate) const fn uuid(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes256,
    ChaCha20,
    Twofish,
}

impl Cipher {
    pub(crate) fn iv_length(self) -> usize {
        match self {
            Self::Aes256 | Self::Twofish => 16,
            Self::ChaCha20 => 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
}

/// The unencrypted KDBX 4 outer header. `bytes` is kept verbatim because the
/// header SHA-256 and HMAC cover it, and a writer reuses it unchanged.
#[derive(Debug, Clone)]
pub struct OuterHeader {
    pub minor_version: u16,
    pub cipher: Cipher,
    pub compression: Compression,
    pub kdf: KdfParameters,
    pub(crate) master_seed: [u8; 32],
    pub(crate) encryption_iv: Vec<u8>,
    pub(crate) public_custom_data: Option<VariantDictionary>,
    pub(crate) bytes: Vec<u8>,
}

impl OuterHeader {
    /// Parses the header and returns it with the number of bytes it occupies,
    /// excluding the trailing SHA-256 and HMAC.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let mut reader = ByteReader::new(data);
        let truncated = KdbxError::InvalidHeader("truncated");
        if reader.u32(KdbxError::NotKdbx)? != SIGNATURE_1
            || reader.u32(KdbxError::NotKdbx)? != SIGNATURE_2_KDBX
        {
            return Err(KdbxError::NotKdbx);
        }
        let minor = reader.u16(truncated)?;
        let major = reader.u16(truncated)?;
        match major {
            4 if SUPPORTED_MINOR_VERSIONS.contains(&minor) => {}
            3 => return Err(KdbxError::Kdbx3Unsupported),
            _ => return Err(KdbxError::UnsupportedVersion { major, minor }),
        }

        let mut cipher = None;
        let mut compression = None;
        let mut master_seed = None;
        let mut encryption_iv = None;
        let mut kdf = None;
        let mut public_custom_data = None;
        loop {
            let field = reader.u8(truncated)?;
            let length = usize::try_from(reader.u32(truncated)?).map_err(|_| truncated)?;
            let value = reader.take(length, truncated)?;
            if reader.position() > MAX_HEADER_LENGTH {
                return Err(KdbxError::LimitExceeded("header length"));
            }
            match field {
                FIELD_END => break,
                FIELD_CIPHER_ID => cipher = Some(parse_cipher(value)?),
                FIELD_COMPRESSION => compression = Some(parse_compression(value)?),
                FIELD_MASTER_SEED => {
                    master_seed = Some(
                        value
                            .try_into()
                            .map_err(|_| KdbxError::InvalidHeader("master seed"))?,
                    )
                }
                FIELD_ENCRYPTION_IV => encryption_iv = Some(value.to_vec()),
                FIELD_KDF_PARAMETERS => {
                    kdf = Some(KdfParameters::from_dictionary(&VariantDictionary::parse(
                        value,
                    )?)?)
                }
                FIELD_PUBLIC_CUSTOM_DATA => {
                    public_custom_data = Some(VariantDictionary::parse(value)?)
                }
                _ => return Err(KdbxError::InvalidHeader("unknown field")),
            }
        }

        let cipher = cipher.ok_or(KdbxError::InvalidHeader("missing cipher"))?;
        let encryption_iv: Vec<u8> =
            encryption_iv.ok_or(KdbxError::InvalidHeader("missing encryption IV"))?;
        if encryption_iv.len() != cipher.iv_length() {
            return Err(KdbxError::InvalidHeader("encryption IV length"));
        }
        let header_length = reader.position();
        let header = Self {
            minor_version: minor,
            cipher,
            compression: compression.ok_or(KdbxError::InvalidHeader("missing compression"))?,
            kdf: kdf.ok_or(KdbxError::InvalidHeader("missing KDF parameters"))?,
            master_seed: master_seed.ok_or(KdbxError::InvalidHeader("missing master seed"))?,
            encryption_iv,
            public_custom_data,
            bytes: data[..header_length].to_vec(),
        };
        Ok((header, header_length))
    }

    /// Plugin data that KeePass clients store unencrypted in the header.
    pub fn public_custom_data(&self) -> Option<&VariantDictionary> {
        self.public_custom_data.as_ref()
    }
}

fn parse_cipher(value: &[u8]) -> Result<Cipher> {
    let id: [u8; 16] = value
        .try_into()
        .map_err(|_| KdbxError::InvalidHeader("cipher id"))?;
    match id {
        CIPHER_AES256 => Ok(Cipher::Aes256),
        CIPHER_CHACHA20 => Ok(Cipher::ChaCha20),
        CIPHER_TWOFISH => Ok(Cipher::Twofish),
        _ => Err(KdbxError::UnsupportedCipher),
    }
}

fn parse_compression(value: &[u8]) -> Result<Compression> {
    let flag: [u8; 4] = value
        .try_into()
        .map_err(|_| KdbxError::InvalidHeader("compression flag"))?;
    match u32::from_le_bytes(flag) {
        0 => Ok(Compression::None),
        1 => Ok(Compression::Gzip),
        _ => Err(KdbxError::UnsupportedCompression),
    }
}
