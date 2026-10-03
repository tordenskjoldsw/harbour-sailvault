use std::str::FromStr;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::base64::decode;
use super::error::{CryptoError, Result};
use super::keys::{SymmetricKey, KEY_LENGTH};

const IV_LENGTH: usize = 16;

/// Symmetric Bitwarden EncString (`<type>.<iv>|<data>[|<mac>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncString {
    /// Type 0: AES-256-CBC without authentication, legacy data only.
    AesCbc256 { iv: [u8; IV_LENGTH], data: Vec<u8> },
    /// Type 2: AES-256-CBC with HMAC-SHA256 over `iv || data`.
    AesCbc256HmacSha256 {
        iv: [u8; IV_LENGTH],
        data: Vec<u8>,
        mac: [u8; KEY_LENGTH],
    },
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(value: &str) -> Result<Self> {
        let (enc_type, payload) = match value.split_once('.') {
            Some((enc_type, payload)) => (
                enc_type
                    .parse::<u8>()
                    .map_err(|_| CryptoError::InvalidEncString)?,
                payload,
            ),
            None if value.split('|').count() == 3 => (1, value),
            None => (0, value),
        };
        let parts: Vec<&str> = payload.split('|').collect();
        match (enc_type, parts.as_slice()) {
            (0, [iv, data]) => Ok(Self::AesCbc256 {
                iv: decode_array(iv)?,
                data: decode(data)?,
            }),
            (2, [iv, data, mac]) => Ok(Self::AesCbc256HmacSha256 {
                iv: decode_array(iv)?,
                data: decode(data)?,
                mac: decode_array(mac)?,
            }),
            (0 | 2, _) => Err(CryptoError::InvalidEncString),
            (other, _) => Err(CryptoError::UnsupportedEncStringType(other)),
        }
    }
}

impl EncString {
    /// The key type must match the string type, so a type 2 string cannot be
    /// rewritten as type 0 to skip the MAC check.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
        match (self, key.mac_key()) {
            (Self::AesCbc256HmacSha256 { iv, data, mac }, Some(mac_key)) => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)
                    .expect("HMAC accepts keys of any length");
                hmac.update(iv);
                hmac.update(data);
                hmac.verify_slice(mac)
                    .map_err(|_| CryptoError::MacMismatch)?;
                aes_cbc_decrypt(key.enc_key(), iv, data)
            }
            (Self::AesCbc256 { iv, data }, None) => aes_cbc_decrypt(key.enc_key(), iv, data),
            _ => Err(CryptoError::WrongKeyType),
        }
    }

    pub fn decrypt_to_string(&self, key: &SymmetricKey) -> Result<Zeroizing<String>> {
        let mut plaintext = self.decrypt(key)?;
        String::from_utf8(std::mem::take(&mut *plaintext))
            .map(Zeroizing::new)
            .map_err(|error| {
                error.into_bytes().zeroize();
                CryptoError::InvalidUtf8
            })
    }
}

fn aes_cbc_decrypt(
    key: &[u8; KEY_LENGTH],
    iv: &[u8; IV_LENGTH],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(data.to_vec());
    let plaintext_length = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?
        .len();
    buffer.truncate(plaintext_length);
    Ok(buffer)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEncString)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IV: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
    const MAC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn parses_type_2() {
        let parsed: EncString = format!("2.{IV}|AAAA|{MAC}").parse().unwrap();
        assert!(matches!(parsed, EncString::AesCbc256HmacSha256 { .. }));
    }

    #[test]
    fn infers_legacy_type_without_prefix() {
        let parsed: EncString = format!("{IV}|AAAA").parse().unwrap();
        assert!(matches!(parsed, EncString::AesCbc256 { .. }));
        assert_eq!(
            format!("{IV}|AAAA|{MAC}").parse::<EncString>(),
            Err(CryptoError::UnsupportedEncStringType(1))
        );
    }

    #[test]
    fn rejects_unsupported_and_malformed_strings() {
        assert_eq!(
            "7.oQEB".parse::<EncString>(),
            Err(CryptoError::UnsupportedEncStringType(7))
        );
        assert_eq!(
            format!("2.{IV}|AAAA").parse::<EncString>(),
            Err(CryptoError::InvalidEncString)
        );
        assert_eq!(
            format!("2.AAAA|AAAA|{MAC}").parse::<EncString>(),
            Err(CryptoError::InvalidEncString)
        );
        assert_eq!(
            "x.AAAA".parse::<EncString>(),
            Err(CryptoError::InvalidEncString)
        );
    }
}
