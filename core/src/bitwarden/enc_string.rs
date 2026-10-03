use std::str::FromStr;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::base64::decode;
use super::error::{ImportError, Result};
use super::keys::{SymmetricKey, KEY_LENGTH};

const IV_LENGTH: usize = 16;
const TYPE_AES_CBC_256_HMAC_SHA256: u8 = 2;

/// Bitwarden EncString type 2 (`2.<iv>|<data>|<mac>`): AES-256-CBC with
/// HMAC-SHA256 over `iv || data`. Exports use no other type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncString {
    iv: [u8; IV_LENGTH],
    data: Vec<u8>,
    mac: [u8; KEY_LENGTH],
}

impl FromStr for EncString {
    type Err = ImportError;

    fn from_str(value: &str) -> Result<Self> {
        let (enc_type, payload) = value.split_once('.').ok_or(ImportError::InvalidEncString)?;
        let enc_type = enc_type
            .parse::<u8>()
            .map_err(|_| ImportError::InvalidEncString)?;
        if enc_type != TYPE_AES_CBC_256_HMAC_SHA256 {
            return Err(ImportError::UnsupportedEncStringType(enc_type));
        }
        match payload.split('|').collect::<Vec<_>>().as_slice() {
            [iv, data, mac] => Ok(Self {
                iv: decode_array(iv)?,
                data: decode(data)?,
                mac: decode_array(mac)?,
            }),
            _ => Err(ImportError::InvalidEncString),
        }
    }
}

impl EncString {
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
        let mut hmac =
            Hmac::<Sha256>::new_from_slice(key.mac_key()).expect("HMAC accepts keys of any length");
        hmac.update(&self.iv);
        hmac.update(&self.data);
        hmac.verify_slice(&self.mac)
            .map_err(|_| ImportError::MacMismatch)?;

        let mut buffer = Zeroizing::new(self.data.clone());
        let plaintext_length =
            cbc::Decryptor::<aes::Aes256>::new(key.enc_key().into(), (&self.iv).into())
                .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                .map_err(|_| ImportError::DecryptionFailed)?
                .len();
        buffer.truncate(plaintext_length);
        Ok(buffer)
    }

    pub fn decrypt_to_string(&self, key: &SymmetricKey) -> Result<Zeroizing<String>> {
        let mut plaintext = self.decrypt(key)?;
        String::from_utf8(std::mem::take(&mut *plaintext))
            .map(Zeroizing::new)
            .map_err(|error| {
                error.into_bytes().zeroize();
                ImportError::InvalidUtf8
            })
    }
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode(value)?
        .try_into()
        .map_err(|_| ImportError::InvalidEncString)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IV: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
    const MAC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn parses_type_2() {
        assert!(format!("2.{IV}|AAAA|{MAC}").parse::<EncString>().is_ok());
    }

    #[test]
    fn rejects_other_types_and_malformed_strings() {
        for (value, error) in [
            (
                "7.oQEB".to_owned(),
                ImportError::UnsupportedEncStringType(7),
            ),
            (
                format!("0.{IV}|AAAA"),
                ImportError::UnsupportedEncStringType(0),
            ),
            (format!("{IV}|AAAA|{MAC}"), ImportError::InvalidEncString),
            (format!("2.{IV}|AAAA"), ImportError::InvalidEncString),
            (format!("2.AAAA|AAAA|{MAC}"), ImportError::InvalidEncString),
            ("x.AAAA".to_owned(), ImportError::InvalidEncString),
        ] {
            assert_eq!(value.parse::<EncString>(), Err(error), "{value}");
        }
    }
}
