use std::io::Read;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use flate2::read::GzDecoder;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::{Cipher, Compression, OuterHeader};
use super::key::KEY_LENGTH;
use super::reader::ByteReader;

const HASH_LENGTH: usize = 32;
const HEADER_HMAC_BLOCK_INDEX: u64 = u64::MAX;
const MAX_PAYLOAD_LENGTH: usize = 256 << 20;
const MAX_XML_LENGTH: usize = 512 << 20;

type HmacSha256 = Hmac<Sha256>;

/// Keys derived from the transformed composite key and the master seed.
pub(crate) struct PayloadKeys {
    cipher_key: Zeroizing<[u8; KEY_LENGTH]>,
    hmac_key: Zeroizing<[u8; 64]>,
}

impl PayloadKeys {
    pub(crate) fn derive(header: &OuterHeader, transformed: &[u8; KEY_LENGTH]) -> Self {
        let mut cipher_key = Zeroizing::new([0u8; KEY_LENGTH]);
        cipher_key.copy_from_slice(
            &Sha256::new()
                .chain_update(header.master_seed)
                .chain_update(transformed)
                .finalize(),
        );
        let mut hmac_key = Zeroizing::new([0u8; 64]);
        hmac_key.copy_from_slice(
            &Sha512::new()
                .chain_update(header.master_seed)
                .chain_update(transformed)
                .chain_update([1u8])
                .finalize(),
        );
        Self {
            cipher_key,
            hmac_key,
        }
    }

    fn block_hmac(&self, index: u64) -> HmacSha256 {
        let block_key = Zeroizing::new(<[u8; 64]>::from(
            Sha512::new()
                .chain_update(index.to_le_bytes())
                .chain_update(self.hmac_key.as_ref())
                .finalize(),
        ));
        HmacSha256::new_from_slice(block_key.as_ref()).expect("HMAC accepts keys of any length")
    }
}

/// Checks the header hash, which detects corruption before the slow KDF
/// runs. The hash is over public data, so a plain comparison is fine.
pub(crate) fn verify_header_hash(
    data: &[u8],
    header: &OuterHeader,
    header_length: usize,
) -> Result<()> {
    let mut reader = ByteReader::new(&data[header_length..]);
    let stored_hash = reader.take(HASH_LENGTH, KdbxError::HeaderCorrupted)?;
    if Sha256::digest(&header.bytes).as_slice() != stored_hash {
        return Err(KdbxError::HeaderCorrupted);
    }
    Ok(())
}

/// Checks the header HMAC (credentials). Returns the offset where the HMAC
/// block stream starts.
pub(crate) fn verify_header_hmac(
    data: &[u8],
    header: &OuterHeader,
    header_length: usize,
    keys: &PayloadKeys,
) -> Result<usize> {
    let mut reader = ByteReader::new(&data[header_length + HASH_LENGTH..]);
    let stored_hmac = reader.take(HASH_LENGTH, KdbxError::HeaderCorrupted)?;
    let mut hmac = keys.block_hmac(HEADER_HMAC_BLOCK_INDEX);
    hmac.update(&header.bytes);
    hmac.verify_slice(stored_hmac)
        .map_err(|_| KdbxError::InvalidCredentials)?;
    Ok(header_length + 2 * HASH_LENGTH)
}

/// Reads the HMAC-protected blocks, decrypts and decompresses them. The
/// result is the inner header followed by the XML document.
pub(crate) fn decrypt(
    data: &[u8],
    header: &OuterHeader,
    keys: &PayloadKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut ciphertext = Vec::new();
    let mut reader = ByteReader::new(data);
    for index in 0u64.. {
        let stored_hmac = reader.take(HASH_LENGTH, KdbxError::PayloadCorrupted)?;
        let length_bytes: [u8; 4] = reader.array(KdbxError::PayloadCorrupted)?;
        let length = usize::try_from(u32::from_le_bytes(length_bytes))
            .map_err(|_| KdbxError::PayloadCorrupted)?;
        let block = reader.take(length, KdbxError::PayloadCorrupted)?;

        let mut hmac = keys.block_hmac(index);
        hmac.update(&index.to_le_bytes());
        hmac.update(&length_bytes);
        hmac.update(block);
        hmac.verify_slice(stored_hmac)
            .map_err(|_| KdbxError::PayloadCorrupted)?;

        if block.is_empty() {
            break;
        }
        if ciphertext.len() + block.len() > MAX_PAYLOAD_LENGTH {
            return Err(KdbxError::LimitExceeded("payload size"));
        }
        ciphertext.extend_from_slice(block);
    }

    let plaintext = decrypt_payload(header, keys, ciphertext)?;
    match header.compression {
        Compression::None => Ok(plaintext),
        Compression::Gzip => gunzip(&plaintext),
    }
}

fn decrypt_payload(
    header: &OuterHeader,
    keys: &PayloadKeys,
    ciphertext: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(ciphertext);
    let key = keys.cipher_key.as_ref();
    let iv = header.encryption_iv.as_slice();
    let plaintext_length = match header.cipher {
        Cipher::Aes256 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| KdbxError::DecryptionFailed)?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| KdbxError::DecryptionFailed)?
            .len(),
        Cipher::Twofish => cbc::Decryptor::<twofish::Twofish>::new_from_slices(key, iv)
            .map_err(|_| KdbxError::DecryptionFailed)?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| KdbxError::DecryptionFailed)?
            .len(),
        Cipher::ChaCha20 => {
            ChaCha20::new_from_slices(key, iv)
                .map_err(|_| KdbxError::DecryptionFailed)?
                .apply_keystream(&mut buffer);
            buffer.len()
        }
    };
    buffer.truncate(plaintext_length);
    Ok(buffer)
}

fn gunzip(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut decompressed = Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_XML_LENGTH).expect("limit fits in u64") + 1;
    GzDecoder::new(compressed)
        .take(limit)
        .read_to_end(&mut decompressed)
        .map_err(|_| KdbxError::DecompressionFailed)?;
    if decompressed.len() > MAX_XML_LENGTH {
        return Err(KdbxError::LimitExceeded("decompressed size"));
    }
    Ok(decompressed)
}
