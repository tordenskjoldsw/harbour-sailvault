use std::fmt;
use std::ops::RangeInclusive;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::enc_string::EncString;
use super::error::{CryptoError, Result};
use super::keys::{SymmetricKey, KEY_LENGTH};

// Lower bounds stop a malicious server from downgrading the KDF to harvest a
// login hash that is cheap to brute-force. Upper bounds keep a hostile server
// from stalling or exhausting the phone.
const PBKDF2_ITERATIONS: RangeInclusive<u32> = 100_000..=5_000_000;
const ARGON2_ITERATIONS: RangeInclusive<u32> = 2..=10;
const ARGON2_MEMORY_MIB: RangeInclusive<u32> = 16..=1024;
const ARGON2_PARALLELISM: RangeInclusive<u32> = 1..=16;

const KDF_TYPE_PBKDF2: u32 = 0;
const KDF_TYPE_ARGON2ID: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Kdf {
    /// Interprets the `kdf`, `kdfIterations`, `kdfMemory` and `kdfParallelism`
    /// fields of a prelogin or token response.
    pub fn from_server(
        kdf_type: u32,
        iterations: u32,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        let kdf = match (kdf_type, memory_mib, parallelism) {
            (KDF_TYPE_PBKDF2, _, _) => Self::Pbkdf2 { iterations },
            (KDF_TYPE_ARGON2ID, Some(memory_mib), Some(parallelism)) => Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            },
            _ => return Err(CryptoError::InvalidKdfParameters),
        };
        kdf.validate()?;
        Ok(kdf)
    }

    fn validate(&self) -> Result<()> {
        let valid = match *self {
            Self::Pbkdf2 { iterations } => PBKDF2_ITERATIONS.contains(&iterations),
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                ARGON2_ITERATIONS.contains(&iterations)
                    && ARGON2_MEMORY_MIB.contains(&memory_mib)
                    && ARGON2_PARALLELISM.contains(&parallelism)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(CryptoError::InvalidKdfParameters)
        }
    }

    pub fn derive_master_key(&self, password: &[u8], email: &str) -> Result<MasterKey> {
        self.validate()?;
        let salt = normalize_email(email);
        let mut master_key = MasterKey([0u8; KEY_LENGTH]);
        match *self {
            Self::Pbkdf2 { iterations } => {
                pbkdf2_hmac::<Sha256>(password, salt.as_bytes(), iterations, &mut master_key.0);
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let params =
                    Params::new(memory_mib * 1024, iterations, parallelism, Some(KEY_LENGTH))
                        .map_err(|_| CryptoError::InvalidKdfParameters)?;
                let salt_hash = Sha256::digest(salt.as_bytes());
                Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                    .hash_password_into(password, &salt_hash, &mut master_key.0)
                    .map_err(|_| CryptoError::InvalidKdfParameters)?;
            }
        }
        Ok(master_key)
    }
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LENGTH]);

impl MasterKey {
    /// The value sent to the server as `password` at login. It proves
    /// knowledge of the master password without revealing the master key.
    pub fn login_hash(&self, password: &[u8]) -> Zeroizing<String> {
        let mut hash = Zeroizing::new([0u8; KEY_LENGTH]);
        pbkdf2_hmac::<Sha256>(&self.0, password, 1, hash.as_mut());
        Zeroizing::new(STANDARD.encode(hash.as_ref()))
    }

    /// Decrypts the protected user key (`Key` in the token response).
    pub fn decrypt_user_key(&self, protected_user_key: &EncString) -> Result<SymmetricKey> {
        let user_key = match protected_user_key {
            EncString::AesCbc256HmacSha256 { .. } => protected_user_key.decrypt(&self.stretch())?,
            EncString::AesCbc256 { .. } => {
                protected_user_key.decrypt(&SymmetricKey::from_parts(self.0, None))?
            }
        };
        SymmetricKey::from_aes_cbc_hmac_bytes(&user_key)
    }

    fn stretch(&self) -> SymmetricKey {
        let hkdf = Hkdf::<Sha256>::from_prk(&self.0)
            .expect("a 32-byte PRK matches the SHA-256 output length");
        let mut enc = [0u8; KEY_LENGTH];
        let mut mac = [0u8; KEY_LENGTH];
        hkdf.expand(b"enc", &mut enc)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hkdf.expand(b"mac", &mut mac)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        SymmetricKey::from_parts(enc, Some(mac))
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(..)")
    }
}
