use std::ops::RangeInclusive;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::uuid;
use super::key::{CompositeKey, KEY_LENGTH};
use super::variant_dictionary::{Value, VariantDictionary};

const KDF_AES_KDBX3: [u8; 16] = uuid(0x7c02bb82_79a74ac0_927d114a_00648238);
const KDF_AES_KDBX4: [u8; 16] = uuid(0xc9d9f39a_628a4460_bf740d08_c18a4fea);
const KDF_ARGON2D: [u8; 16] = uuid(0xef636ddf_8c29444b_91f7a9a4_03e30a0c);
const KDF_ARGON2ID: [u8; 16] = uuid(0x9e298b19_56db4773_b23dfc3e_c6f0a1e6);

// Generous bounds for reading the user's own databases; they only stop a
// crafted file from stalling or exhausting the phone.
const AES_ROUNDS: RangeInclusive<u64> = 1..=1_000_000_000;
const ARGON2_ITERATIONS: RangeInclusive<u64> = 1..=4096;
const ARGON2_MEMORY_BYTES: RangeInclusive<u64> = (8 << 10)..=(2 << 30);
const ARGON2_PARALLELISM: RangeInclusive<u32> = 1..=64;
const ARGON2_SALT_LENGTH: RangeInclusive<usize> = 8..=64;
const ARGON2_VERSION_10: u32 = 0x10;
const ARGON2_VERSION_13: u32 = 0x13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Variant {
    Argon2d,
    Argon2id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParameters {
    AesKdf {
        rounds: u64,
        seed: [u8; 32],
    },
    Argon2 {
        variant: Argon2Variant,
        iterations: u64,
        memory_bytes: u64,
        parallelism: u32,
        version: u32,
        salt: Vec<u8>,
    },
}

impl KdfParameters {
    pub(crate) fn from_dictionary(dictionary: &VariantDictionary) -> Result<Self> {
        let id = match dictionary.get("$UUID") {
            Some(Value::ByteArray(id)) => <[u8; 16]>::try_from(id.as_slice())
                .map_err(|_| KdbxError::InvalidHeader("KDF id"))?,
            _ => return Err(KdbxError::InvalidHeader("KDF id")),
        };
        let parameters = match id {
            KDF_AES_KDBX3 | KDF_AES_KDBX4 => Self::AesKdf {
                rounds: uint64(dictionary, "R")?,
                seed: bytes(dictionary, "S")?
                    .try_into()
                    .map_err(|_| KdbxError::InvalidHeader("AES-KDF seed"))?,
            },
            KDF_ARGON2D | KDF_ARGON2ID => {
                // Secret and associated data are allowed by the format, but no
                // KeePass client writes them; refuse rather than misderive.
                if dictionary.get("K").is_some() || dictionary.get("A").is_some() {
                    return Err(KdbxError::UnsupportedKdf);
                }
                Self::Argon2 {
                    variant: if id == KDF_ARGON2D {
                        Argon2Variant::Argon2d
                    } else {
                        Argon2Variant::Argon2id
                    },
                    iterations: uint64(dictionary, "I")?,
                    memory_bytes: uint64(dictionary, "M")?,
                    parallelism: match dictionary.get("P") {
                        Some(Value::UInt32(parallelism)) => *parallelism,
                        _ => return Err(KdbxError::InvalidHeader("Argon2 parallelism")),
                    },
                    version: match dictionary.get("V") {
                        Some(Value::UInt32(version)) => *version,
                        _ => return Err(KdbxError::InvalidHeader("Argon2 version")),
                    },
                    salt: bytes(dictionary, "S")?.to_vec(),
                }
            }
            _ => return Err(KdbxError::UnsupportedKdf),
        };
        parameters.validate()?;
        Ok(parameters)
    }

    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::AesKdf { rounds, .. } => AES_ROUNDS.contains(rounds),
            Self::Argon2 {
                iterations,
                memory_bytes,
                parallelism,
                version,
                salt,
                ..
            } => {
                ARGON2_ITERATIONS.contains(iterations)
                    && ARGON2_MEMORY_BYTES.contains(memory_bytes)
                    && ARGON2_PARALLELISM.contains(parallelism)
                    && [ARGON2_VERSION_10, ARGON2_VERSION_13].contains(version)
                    && ARGON2_SALT_LENGTH.contains(&salt.len())
            }
        };
        if valid {
            Ok(())
        } else {
            Err(KdbxError::KdfParametersOutOfRange)
        }
    }

    /// Runs the KDF over the composite key. This is the slow step of
    /// unlocking and must not run on the UI thread.
    pub fn transform(&self, key: &CompositeKey) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
        self.validate()?;
        let mut transformed = Zeroizing::new(*key.as_bytes());
        match self {
            Self::AesKdf { rounds, seed } => {
                let cipher = Aes256::new(seed.into());
                let (first, second) = transformed.split_at_mut(16);
                for _ in 0..*rounds {
                    cipher.encrypt_block(first.into());
                    cipher.encrypt_block(second.into());
                }
                let digest = Sha256::digest(transformed.as_ref());
                transformed.copy_from_slice(&digest);
            }
            Self::Argon2 {
                variant,
                iterations,
                memory_bytes,
                parallelism,
                version,
                salt,
            } => {
                let algorithm = match variant {
                    Argon2Variant::Argon2d => Algorithm::Argon2d,
                    Argon2Variant::Argon2id => Algorithm::Argon2id,
                };
                let version = if *version == ARGON2_VERSION_10 {
                    Version::V0x10
                } else {
                    Version::V0x13
                };
                let out_of_range = |_| KdbxError::KdfParametersOutOfRange;
                let params = Params::new(
                    u32::try_from(memory_bytes / 1024).map_err(out_of_range)?,
                    u32::try_from(*iterations).map_err(out_of_range)?,
                    *parallelism,
                    Some(KEY_LENGTH),
                )
                .map_err(|_| KdbxError::KdfParametersOutOfRange)?;
                Argon2::new(algorithm, version, params)
                    .hash_password_into(key.as_bytes(), salt, transformed.as_mut())
                    .map_err(|_| KdbxError::KdfParametersOutOfRange)?;
            }
        }
        Ok(transformed)
    }
}

fn uint64(dictionary: &VariantDictionary, name: &'static str) -> Result<u64> {
    match dictionary.get(name) {
        Some(Value::UInt64(value)) => Ok(*value),
        _ => Err(KdbxError::InvalidHeader("KDF parameter")),
    }
}

fn bytes<'a>(dictionary: &'a VariantDictionary, name: &'static str) -> Result<&'a [u8]> {
    match dictionary.get(name) {
        Some(Value::ByteArray(value)) => Ok(value),
        _ => Err(KdbxError::InvalidHeader("KDF parameter")),
    }
}
