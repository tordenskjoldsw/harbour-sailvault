use std::ops::RangeInclusive;

use argon2::{Algorithm, Params, Version};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::error::{ImportError, Result};
use super::keys::{SymmetricKey, KEY_LENGTH};
use crate::argon2_memory;

// Exports use the account's KDF settings, so the lower bounds follow what
// Bitwarden and Vaultwarden accept for accounts. The upper bounds keep a
// crafted file from stalling or exhausting the phone.
const PBKDF2_ITERATIONS: RangeInclusive<u32> = 5_000..=5_000_000;
const ARGON2_ITERATIONS: RangeInclusive<u32> = 1..=10;
const ARGON2_MEMORY_MIB: RangeInclusive<u32> = 15..=1024;
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
    /// Interprets the `kdfType`, `kdfIterations`, `kdfMemory` and
    /// `kdfParallelism` fields of a password-protected export.
    pub fn from_export(
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
            _ => return Err(ImportError::InvalidKdfParameters),
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
            Err(ImportError::InvalidKdfParameters)
        }
    }

    /// Derives the export key: KDF over the password with the export's `salt`
    /// string (its UTF-8 bytes, not base64-decoded), stretched with
    /// HKDF-Expand into encryption and MAC keys.
    pub fn derive_export_key(&self, password: &[u8], salt: &str) -> Result<SymmetricKey> {
        self.validate()?;
        let mut derived = Zeroizing::new([0u8; KEY_LENGTH]);
        match *self {
            Self::Pbkdf2 { iterations } => {
                pbkdf2_hmac::<Sha256>(password, salt.as_bytes(), iterations, derived.as_mut());
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let params =
                    Params::new(memory_mib * 1024, iterations, parallelism, Some(KEY_LENGTH))
                        .map_err(|_| ImportError::InvalidKdfParameters)?;
                argon2_memory::hash_into(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    params,
                    password,
                    &Sha256::digest(salt.as_bytes()),
                    derived.as_mut(),
                )
                .map_err(|_| ImportError::InvalidKdfParameters)?;
            }
        }
        Ok(stretch(&derived))
    }
}

fn stretch(derived: &[u8; KEY_LENGTH]) -> SymmetricKey {
    let hkdf =
        Hkdf::<Sha256>::from_prk(derived).expect("a 32-byte PRK matches the SHA-256 output length");
    let mut enc = [0u8; KEY_LENGTH];
    let mut mac = [0u8; KEY_LENGTH];
    hkdf.expand(b"enc", &mut enc)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    hkdf.expand(b"mac", &mut mac)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SymmetricKey::new(enc, mac)
}
