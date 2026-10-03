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
    /// Filled in place through `parts_mut`, so no copy of the key is left
    /// on the stack.
    pub(crate) fn zeroed() -> Self {
        Self {
            enc: [0; KEY_LENGTH],
            mac: [0; KEY_LENGTH],
        }
    }

    pub(crate) fn parts_mut(&mut self) -> (&mut [u8; KEY_LENGTH], &mut [u8; KEY_LENGTH]) {
        (&mut self.enc, &mut self.mac)
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
