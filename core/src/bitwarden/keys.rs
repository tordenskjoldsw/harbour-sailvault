use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LENGTH: usize = 32;

/// AES-256-CBC key with its HMAC-SHA256 key (EncString type 2).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; KEY_LENGTH],
    mac: [u8; KEY_LENGTH],
}

impl SymmetricKey {
    pub(crate) fn new(enc: [u8; KEY_LENGTH], mac: [u8; KEY_LENGTH]) -> Self {
        Self { enc, mac }
    }

    pub(crate) fn enc_key(&self) -> &[u8; KEY_LENGTH] {
        &self.enc
    }

    pub(crate) fn mac_key(&self) -> &[u8; KEY_LENGTH] {
        &self.mac
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}
