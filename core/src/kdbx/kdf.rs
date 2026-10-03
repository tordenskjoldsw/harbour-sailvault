use std::ops::RangeInclusive;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use argon2::{Algorithm, Params, Version};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::uuid;
use super::key::{CompositeKey, KEY_LENGTH};
use super::variant_dictionary::{Value, VariantDictionary};
use crate::argon2_memory::{self, Argon2Failure};
use crate::random;

// Named as in KeePassXC (KeePass2.cpp): the KDBX 3 UUID marks AES-KDF in KDBX
// 3.1 files, the KDBX 4 UUID is the one KeePass 2.x writes in KDBX 4.
const KDF_AES_KDBX3: [u8; 16] = uuid(0xc9d9f39a_628a4460_bf740d08_c18a4fea);
const KDF_AES_KDBX4: [u8; 16] = uuid(0x7c02bb82_79a74ac0_927d114a_00648238);
const KDF_ARGON2D: [u8; 16] = uuid(0xef636ddf_8c29444b_91f7a9a4_03e30a0c);
const KDF_ARGON2ID: [u8; 16] = uuid(0x9e298b19_56db4773_b23dfc3e_c6f0a1e6);

// Bounds for reading the user's own databases; they stop a crafted file from
// stalling or exhausting the phone before its HMAC can be checked. The work
// cap allows about a minute of Argon2 on the Jolla Phone (about 60 ms per
// iteration per 64 MiB).
const AES_ROUNDS: RangeInclusive<u64> = 1..=1_000_000_000;
const ARGON2_ITERATIONS: RangeInclusive<u64> = 1..=1000;
const ARGON2_MEMORY_BYTES: RangeInclusive<u64> = (8 << 10)..=(1 << 30);
const ARGON2_MAX_WORK_BYTES: u64 = 64 << 30;
const ARGON2_PARALLELISM: RangeInclusive<u32> = 1..=64;
const ARGON2_SALT_LENGTH: RangeInclusive<usize> = 8..=64;
const ARGON2_VERSION_10: u32 = 0x10;
pub(super) const ARGON2_VERSION_13: u32 = 0x13;
// KeePassXC's `Kdf::randomizeSeed` draws 32 bytes for both KDFs.
const SEED_LENGTH: usize = 32;

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

    /// The same parameters with a fresh seed. KeePassXC and KeePass draw a
    /// new one on every save.
    pub(crate) fn with_new_seed(&self) -> Result<Self> {
        let mut renewed = self.clone();
        match &mut renewed {
            Self::AesKdf { seed, .. } => random::fill(seed)?,
            Self::Argon2 { salt, .. } => *salt = random::array::<SEED_LENGTH>()?.to_vec(),
        }
        Ok(renewed)
    }

    /// Keys in the order KeePassXC writes them (sorted, `$UUID` first). A
    /// KDBX 4 file always carries the KDBX 4 AES-KDF UUID.
    pub(crate) fn to_dictionary(&self) -> VariantDictionary {
        let entries = match self {
            Self::AesKdf { rounds, seed } => vec![
                ("$UUID".to_owned(), Value::ByteArray(KDF_AES_KDBX4.to_vec())),
                ("R".to_owned(), Value::UInt64(*rounds)),
                ("S".to_owned(), Value::ByteArray(seed.to_vec())),
            ],
            Self::Argon2 {
                variant,
                iterations,
                memory_bytes,
                parallelism,
                version,
                salt,
            } => {
                let id = match variant {
                    Argon2Variant::Argon2d => KDF_ARGON2D,
                    Argon2Variant::Argon2id => KDF_ARGON2ID,
                };
                vec![
                    ("$UUID".to_owned(), Value::ByteArray(id.to_vec())),
                    ("I".to_owned(), Value::UInt64(*iterations)),
                    ("M".to_owned(), Value::UInt64(*memory_bytes)),
                    ("P".to_owned(), Value::UInt32(*parallelism)),
                    ("S".to_owned(), Value::ByteArray(salt.clone())),
                    ("V".to_owned(), Value::UInt32(*version)),
                ]
            }
        };
        VariantDictionary::from_entries(entries)
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
                    && memory_bytes.saturating_mul(*iterations) <= ARGON2_MAX_WORK_BYTES
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
                let hasher = Sha256::new().chain_update(transformed.as_ref());
                hasher.finalize_into(GenericArray::from_mut_slice(transformed.as_mut()));
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
                argon2_memory::hash_into(
                    algorithm,
                    version,
                    params,
                    key.as_bytes(),
                    salt,
                    transformed.as_mut(),
                )
                .map_err(|failure| match failure {
                    Argon2Failure::OutOfMemory => KdbxError::LimitExceeded("Argon2 memory"),
                    Argon2Failure::InvalidParameters => KdbxError::KdfParametersOutOfRange,
                })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_kdf_uuids_match_keepassxc() {
        assert_eq!(
            KDF_AES_KDBX3,
            [
                0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a,
                0x4f, 0xea
            ]
        );
        assert_eq!(
            KDF_AES_KDBX4,
            [
                0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64,
                0x82, 0x38
            ]
        );
    }

    fn argon2(iterations: u64, memory_bytes: u64) -> KdfParameters {
        KdfParameters::Argon2 {
            variant: Argon2Variant::Argon2id,
            iterations,
            memory_bytes,
            parallelism: 2,
            version: ARGON2_VERSION_13,
            salt: vec![1; 32],
        }
    }

    #[test]
    fn argon2_work_is_bounded_before_running() {
        let key = CompositeKey::new(Some(b"x"), None).unwrap();
        for parameters in [
            argon2(2, 2 << 30),
            argon2(1001, 8 << 20),
            argon2(100, 1 << 30),
        ] {
            assert_eq!(
                parameters.transform(&key).map(|_| ()),
                Err(KdbxError::KdfParametersOutOfRange)
            );
        }
        assert!(argon2(2, 1 << 20).transform(&key).is_ok());
    }

    #[test]
    fn dictionary_round_trips_and_new_seed_changes_only_the_seed() {
        let aes = KdfParameters::AesKdf {
            rounds: 60_000,
            seed: [5; 32],
        };
        for parameters in [aes, argon2(3, 16 << 20)] {
            let dictionary = parameters.to_dictionary();
            assert_eq!(
                KdfParameters::from_dictionary(&dictionary).unwrap(),
                parameters
            );
            assert_eq!(
                VariantDictionary::parse(&dictionary.serialize().unwrap()).unwrap(),
                dictionary
            );

            let renewed = parameters.with_new_seed().unwrap();
            assert_ne!(renewed, parameters);
            let seedless = |p: &KdfParameters| {
                let mut p = p.clone();
                match &mut p {
                    KdfParameters::AesKdf { seed, .. } => *seed = [0; 32],
                    KdfParameters::Argon2 { salt, .. } => salt.clear(),
                }
                p
            };
            assert_eq!(seedless(&renewed), seedless(&parameters));
        }
    }
}
