use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::{CryptoError, Result};

pub const KEY_LENGTH: usize = 32;
const AES_CBC_HMAC_KEY_LENGTH: usize = 2 * KEY_LENGTH;

/// AES-256 key, with an HMAC-SHA256 key for authenticated encryption
/// (EncString type 2) or without one for legacy data (type 0).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; KEY_LENGTH],
    mac: Option<[u8; KEY_LENGTH]>,
}

impl SymmetricKey {
    /// Builds a key from the 64-byte `enc || mac` layout used for user,
    /// organization and cipher keys. Longer keys belong to V2 accounts.
    pub fn from_aes_cbc_hmac_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > AES_CBC_HMAC_KEY_LENGTH {
            return Err(CryptoError::UnsupportedKeyFormat);
        }
        if bytes.len() != AES_CBC_HMAC_KEY_LENGTH {
            return Err(CryptoError::InvalidKey);
        }
        let mut enc = [0u8; KEY_LENGTH];
        let mut mac = [0u8; KEY_LENGTH];
        enc.copy_from_slice(&bytes[..KEY_LENGTH]);
        mac.copy_from_slice(&bytes[KEY_LENGTH..]);
        Ok(Self {
            enc,
            mac: Some(mac),
        })
    }

    pub(crate) fn from_parts(enc: [u8; KEY_LENGTH], mac: Option<[u8; KEY_LENGTH]>) -> Self {
        Self { enc, mac }
    }

    pub(crate) fn enc_key(&self) -> &[u8; KEY_LENGTH] {
        &self.enc
    }

    pub(crate) fn mac_key(&self) -> Option<&[u8; KEY_LENGTH]> {
        self.mac.as_ref()
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}
