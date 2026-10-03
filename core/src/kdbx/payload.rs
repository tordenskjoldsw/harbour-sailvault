use std::io::{Read, Write};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use hmac::{Hmac, Mac};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::{Cipher, Compression, OuterHeader};
use super::key::KEY_LENGTH;
use super::reader::ByteReader;
use crate::secret::{ByteSink, SecretBuffer};

const HASH_LENGTH: usize = 32;
const HEADER_HMAC_BLOCK_INDEX: u64 = u64::MAX;
const MAX_PAYLOAD_LENGTH: usize = 256 << 20;
const MAX_XML_LENGTH: usize = 512 << 20;
// KeePassXC's HmacBlockStream block size.
const BLOCK_LENGTH: usize = 1 << 20;
const CBC_BLOCK_LENGTH: usize = 16;
const GUNZIP_CHUNK_LENGTH: usize = 64 << 10;

type HmacSha256 = Hmac<Sha256>;

/// Keys derived from the transformed composite key and the master seed.
pub(crate) struct PayloadKeys {
    cipher_key: Zeroizing<[u8; KEY_LENGTH]>,
    hmac_key: Zeroizing<[u8; 64]>,
}

impl PayloadKeys {
    pub(crate) fn derive(header: &OuterHeader, transformed: &[u8; KEY_LENGTH]) -> Self {
        let mut cipher_key = Zeroizing::new([0u8; KEY_LENGTH]);
        Sha256::new()
            .chain_update(header.master_seed)
            .chain_update(transformed)
            .finalize_into(GenericArray::from_mut_slice(cipher_key.as_mut()));
        let mut hmac_key = Zeroizing::new([0u8; 64]);
        Sha512::new()
            .chain_update(header.master_seed)
            .chain_update(transformed)
            .chain_update([1u8])
            .finalize_into(GenericArray::from_mut_slice(hmac_key.as_mut()));
        Self {
            cipher_key,
            hmac_key,
        }
    }

    fn block_hmac(&self, index: u64) -> HmacSha256 {
        let mut block_key = Zeroizing::new([0u8; 64]);
        Sha512::new()
            .chain_update(index.to_le_bytes())
            .chain_update(self.hmac_key.as_ref())
            .finalize_into(GenericArray::from_mut_slice(block_key.as_mut()));
        HmacSha256::new_from_slice(block_key.as_ref()).expect("HMAC accepts keys of any length")
    }

    fn header_hmac(&self, header: &OuterHeader) -> HmacSha256 {
        let mut hmac = self.block_hmac(HEADER_HMAC_BLOCK_INDEX);
        hmac.update(&header.bytes);
        hmac
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
    keys.header_hmac(header)
        .verify_slice(stored_hmac)
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

/// The gzip trailer's size field sizes the output, so it rarely has to grow.
/// The payload is authenticated at this point; the limit still applies.
fn gunzip(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let stated_length = compressed
        .len()
        .checked_sub(4)
        .and_then(|start| compressed[start..].try_into().ok())
        .map_or(0, |size: [u8; 4]| u32::from_le_bytes(size) as usize);
    let mut decompressed = SecretBuffer::with_capacity(stated_length.min(MAX_XML_LENGTH));
    let mut decoder = GzDecoder::new(compressed);
    let mut chunk = Zeroizing::new(vec![0u8; GUNZIP_CHUNK_LENGTH]);
    loop {
        let length = decoder
            .read(&mut chunk)
            .map_err(|_| KdbxError::DecompressionFailed)?;
        if length == 0 {
            break;
        }
        if decompressed.len() + length > MAX_XML_LENGTH {
            return Err(KdbxError::LimitExceeded("decompressed size"));
        }
        decompressed.extend_from_slice(&chunk[..length]);
    }
    Ok(decompressed.into_inner())
}

/// Appends the header SHA-256 and HMAC that follow the header in the file.
pub(crate) fn write_header_authentication(
    header: &OuterHeader,
    keys: &PayloadKeys,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&Sha256::digest(&header.bytes));
    out.extend_from_slice(&keys.header_hmac(header).finalize().into_bytes());
}

/// Compresses and encrypts the inner header and XML, then appends them as
/// HMAC-protected blocks ending with an empty block.
pub(crate) fn encrypt(
    plaintext: &[u8],
    header: &OuterHeader,
    keys: &PayloadKeys,
    out: &mut Vec<u8>,
) -> Result<()> {
    let compressed = match header.compression {
        Compression::None => {
            let mut copy = SecretBuffer::with_capacity(padded_length(plaintext.len()));
            copy.extend_from_slice(plaintext);
            copy
        }
        Compression::Gzip => gzip(plaintext)?,
    };
    let ciphertext = encrypt_payload(header, keys, compressed)?;
    let blocks = ciphertext
        .chunks(BLOCK_LENGTH)
        .chain(std::iter::once(&[][..]));
    for (index, block) in (0u64..).zip(blocks) {
        let length = u32::try_from(block.len()).expect("blocks are at most BLOCK_LENGTH");
        let mut hmac = keys.block_hmac(index);
        hmac.update(&index.to_le_bytes());
        hmac.update(&length.to_le_bytes());
        hmac.update(block);
        out.extend_from_slice(&hmac.finalize().into_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(block);
    }
    Ok(())
}

fn encrypt_payload(
    header: &OuterHeader,
    keys: &PayloadKeys,
    mut plaintext: SecretBuffer,
) -> Result<Vec<u8>> {
    let key = keys.cipher_key.as_ref();
    let iv = header.encryption_iv.as_slice();
    let plaintext_length = plaintext.len();
    if header.cipher != Cipher::ChaCha20 {
        plaintext.resize(padded_length(plaintext_length));
    }
    let mut buffer = plaintext.into_inner();
    match header.cipher {
        Cipher::Aes256 => {
            cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| KdbxError::DecryptionFailed)?
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext_length)
                .map_err(|_| KdbxError::DecryptionFailed)?;
        }
        Cipher::Twofish => {
            cbc::Encryptor::<twofish::Twofish>::new_from_slices(key, iv)
                .map_err(|_| KdbxError::DecryptionFailed)?
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext_length)
                .map_err(|_| KdbxError::DecryptionFailed)?;
        }
        Cipher::ChaCha20 => ChaCha20::new_from_slices(key, iv)
            .map_err(|_| KdbxError::DecryptionFailed)?
            .apply_keystream(&mut buffer),
    }
    Ok(std::mem::take(&mut *buffer))
}

/// PKCS#7 always adds between 1 and 16 bytes.
fn padded_length(length: usize) -> usize {
    length + CBC_BLOCK_LENGTH - length % CBC_BLOCK_LENGTH
}

/// The output starts at a quarter of the input, typical for KeePass XML, and
/// grows through `SecretBuffer` when needed.
fn gzip(data: &[u8]) -> Result<SecretBuffer> {
    let output = SecretBuffer::with_capacity(data.len() / 4 + CBC_BLOCK_LENGTH);
    let mut encoder = GzEncoder::new(output, flate2::Compression::default());
    encoder
        .write_all(data)
        .and_then(|_| encoder.finish())
        .map_err(|_| KdbxError::CompressionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx::kdf::KdfParameters;

    fn header(cipher: Cipher, compression: Compression) -> OuterHeader {
        OuterHeader {
            minor_version: 0,
            cipher,
            compression,
            kdf: KdfParameters::AesKdf {
                rounds: 1,
                seed: [0; 32],
            },
            master_seed: [3; 32],
            encryption_iv: vec![4; cipher.iv_length()],
            public_custom_data: None,
            bytes: b"header bytes".to_vec(),
        }
    }

    #[test]
    fn encrypted_payload_decrypts_back_for_every_cipher_and_size() {
        let transformed = [7u8; KEY_LENGTH];
        let large: Vec<u8> = (0..(2 * BLOCK_LENGTH + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        for cipher in [Cipher::Aes256, Cipher::ChaCha20, Cipher::Twofish] {
            for compression in [Compression::None, Compression::Gzip] {
                let header = header(cipher, compression);
                let keys = PayloadKeys::derive(&header, &transformed);
                for plaintext in [&b""[..], b"short", &[0u8; 16], &large] {
                    let mut file = Vec::new();
                    write_header_authentication(&header, &keys, &mut file);
                    encrypt(plaintext, &header, &keys, &mut file).unwrap();
                    verify_header_hash(&file, &header, 0).unwrap();
                    let start = verify_header_hmac(&file, &header, 0, &keys).unwrap();
                    let decrypted = decrypt(&file[start..], &header, &keys).unwrap();
                    assert_eq!(
                        decrypted.as_slice(),
                        plaintext,
                        "{cipher:?} {compression:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn tampered_block_is_rejected() {
        let header = header(Cipher::Aes256, Compression::None);
        let keys = PayloadKeys::derive(&header, &[1; KEY_LENGTH]);
        let mut file = Vec::new();
        encrypt(b"payload", &header, &keys, &mut file).unwrap();
        let last = file.len() - 1 - 36;
        file[last] ^= 1;
        assert_eq!(
            decrypt(&file, &header, &keys).map(|_| ()),
            Err(KdbxError::PayloadCorrupted)
        );
    }
}
