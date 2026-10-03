use std::fmt;
use std::str::FromStr;

use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::base64::decode;
use super::error::{CryptoError, Result};

/// RSA-encrypted Bitwarden EncString (`<type>.<data>`), used for
/// organization keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsymmetricEncString {
    /// Type 3: RSA-2048 OAEP with SHA-256.
    RsaOaepSha256(Vec<u8>),
    /// Type 4: RSA-2048 OAEP with SHA-1, the type servers produce today.
    RsaOaepSha1(Vec<u8>),
}

impl FromStr for AsymmetricEncString {
    type Err = CryptoError;

    fn from_str(value: &str) -> Result<Self> {
        let (enc_type, payload) = value.split_once('.').ok_or(CryptoError::InvalidEncString)?;
        let enc_type = enc_type
            .parse::<u8>()
            .map_err(|_| CryptoError::InvalidEncString)?;
        match enc_type {
            3 => Ok(Self::RsaOaepSha256(decode(payload)?)),
            4 => Ok(Self::RsaOaepSha1(decode(payload)?)),
            other => Err(CryptoError::UnsupportedEncStringType(other)),
        }
    }
}

pub struct PrivateKey(RsaPrivateKey);

impl PrivateKey {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        RsaPrivateKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    pub fn decrypt(&self, enc_string: &AsymmetricEncString) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = match enc_string {
            AsymmetricEncString::RsaOaepSha256(data) => self.0.decrypt(Oaep::new::<Sha256>(), data),
            AsymmetricEncString::RsaOaepSha1(data) => self.0.decrypt(Oaep::new::<Sha1>(), data),
        };
        plaintext
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_and_malformed_strings() {
        assert_eq!(
            "6.AAAA|AAAA".parse::<AsymmetricEncString>(),
            Err(CryptoError::UnsupportedEncStringType(6))
        );
        assert_eq!(
            "AAAA".parse::<AsymmetricEncString>(),
            Err(CryptoError::InvalidEncString)
        );
        assert_eq!(
            "4.not base64".parse::<AsymmetricEncString>(),
            Err(CryptoError::InvalidEncString)
        );
    }
}
