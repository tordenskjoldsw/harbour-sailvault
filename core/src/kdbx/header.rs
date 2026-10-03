use super::error::{KdbxError, Result};
use super::kdf::KdfParameters;
use super::reader::ByteReader;
use super::variant_dictionary::VariantDictionary;
use crate::random;

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2_KDBX: u32 = 0xB54B_FB67;
const MAJOR_VERSION: u16 = 4;
const SUPPORTED_MINOR_VERSIONS: [u16; 2] = [0, 1];
const MAX_HEADER_LENGTH: usize = 1 << 20;

const FIELD_END: u8 = 0;
const FIELD_COMMENT: u8 = 1;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_COMPRESSION: u8 = 3;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_ENCRYPTION_IV: u8 = 7;
const FIELD_KDF_PARAMETERS: u8 = 11;
const FIELD_PUBLIC_CUSTOM_DATA: u8 = 12;
// The end marker's payload, as KeePass and KeePassXC write it.
const END_OF_HEADER: &[u8] = b"\r\n\r\n";

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

    fn id(self) -> [u8; 16] {
        match self {
            Self::Aes256 => CIPHER_AES256,
            Self::ChaCha20 => CIPHER_CHACHA20,
            Self::Twofish => CIPHER_TWOFISH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
}

impl Compression {
    fn flag(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Gzip => 1,
        }
    }
}

/// The unencrypted KDBX 4 outer header. `bytes` is its serialized form,
/// which the header SHA-256 and HMAC cover.
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
            MAJOR_VERSION if SUPPORTED_MINOR_VERSIONS.contains(&minor) => {}
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
                // Free text that KeePass 2.x defines and KeePassXC ignores.
                FIELD_COMMENT => {}
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

    /// The header for the next save: same settings, fresh master seed,
    /// encryption IV and KDF seed, as KeePassXC draws them on every write
    /// (`Kdbx4Writer.cpp`, `Database::setKey` with `updateTransformSalt`).
    pub(crate) fn renewed(&self) -> Result<Self> {
        let mut encryption_iv = vec![0u8; self.cipher.iv_length()];
        random::fill(&mut encryption_iv)?;
        let mut header = Self {
            minor_version: self.minor_version,
            cipher: self.cipher,
            compression: self.compression,
            kdf: self.kdf.with_new_seed()?,
            master_seed: random::array()?,
            encryption_iv,
            public_custom_data: self.public_custom_data.clone(),
            bytes: Vec::new(),
        };
        header.bytes = header.serialize()?;
        Ok(header)
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&SIGNATURE_1.to_le_bytes());
        out.extend_from_slice(&SIGNATURE_2_KDBX.to_le_bytes());
        out.extend_from_slice(&self.minor_version.to_le_bytes());
        out.extend_from_slice(&MAJOR_VERSION.to_le_bytes());
        write_field(&mut out, FIELD_CIPHER_ID, &self.cipher.id())?;
        write_field(
            &mut out,
            FIELD_COMPRESSION,
            &self.compression.flag().to_le_bytes(),
        )?;
        write_field(&mut out, FIELD_MASTER_SEED, &self.master_seed)?;
        write_field(&mut out, FIELD_ENCRYPTION_IV, &self.encryption_iv)?;
        write_field(
            &mut out,
            FIELD_KDF_PARAMETERS,
            &self.kdf.to_dictionary().serialize()?,
        )?;
        if let Some(data) = &self.public_custom_data {
            write_field(&mut out, FIELD_PUBLIC_CUSTOM_DATA, &data.serialize()?)?;
        }
        write_field(&mut out, FIELD_END, END_OF_HEADER)?;
        Ok(out)
    }

    /// Plugin data that KeePass clients store unencrypted in the header.
    pub fn public_custom_data(&self) -> Option<&VariantDictionary> {
        self.public_custom_data.as_ref()
    }
}

/// Writes a header field as both the outer and the inner header encode it:
/// id, little-endian length, value.
pub(crate) fn write_field(out: &mut Vec<u8>, id: u8, value: &[u8]) -> Result<()> {
    let length =
        u32::try_from(value.len()).map_err(|_| KdbxError::LimitExceeded("header field"))?;
    out.push(id);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx::kdf::Argon2Variant;
    use crate::kdbx::variant_dictionary::Value;

    fn header(cipher: Cipher, public_custom_data: Option<VariantDictionary>) -> OuterHeader {
        OuterHeader {
            minor_version: 1,
            cipher,
            compression: Compression::Gzip,
            kdf: KdfParameters::Argon2 {
                variant: Argon2Variant::Argon2id,
                iterations: 2,
                memory_bytes: 8 << 20,
                parallelism: 2,
                version: 0x13,
                salt: vec![7; 32],
            },
            master_seed: [1; 32],
            encryption_iv: vec![2; cipher.iv_length()],
            public_custom_data,
            bytes: Vec::new(),
        }
    }

    fn fields_equal(a: &OuterHeader, b: &OuterHeader) -> bool {
        a.minor_version == b.minor_version
            && a.cipher == b.cipher
            && a.compression == b.compression
            && a.kdf == b.kdf
            && a.master_seed == b.master_seed
            && a.encryption_iv == b.encryption_iv
            && a.public_custom_data == b.public_custom_data
    }

    #[test]
    fn serialized_header_parses_back_to_the_same_fields() {
        let plugin_data = VariantDictionary::from_entries(vec![(
            "Plugin".to_owned(),
            Value::String("kept".to_owned()),
        )]);
        for original in [
            header(Cipher::ChaCha20, None),
            header(Cipher::Aes256, Some(plugin_data)),
        ] {
            let bytes = original.serialize().unwrap();
            let (parsed, length) = OuterHeader::parse(&bytes).unwrap();
            assert_eq!(length, bytes.len());
            assert_eq!(parsed.bytes, bytes);
            assert!(fields_equal(&parsed, &original));
            assert!(bytes.ends_with(b"\r\n\r\n"));
        }
    }

    #[test]
    fn renewed_header_keeps_settings_and_changes_every_seed() {
        let original = header(Cipher::Twofish, None);
        let renewed = original.renewed().unwrap();
        assert_eq!(renewed.minor_version, original.minor_version);
        assert_eq!(renewed.cipher, original.cipher);
        assert_eq!(renewed.compression, original.compression);
        assert_ne!(renewed.master_seed, original.master_seed);
        assert_ne!(renewed.encryption_iv, original.encryption_iv);
        assert_eq!(renewed.encryption_iv.len(), original.encryption_iv.len());
        assert_ne!(renewed.kdf, original.kdf);
        let (parsed, _) = OuterHeader::parse(&renewed.bytes).unwrap();
        assert!(fields_equal(&parsed, &renewed));
    }
}
