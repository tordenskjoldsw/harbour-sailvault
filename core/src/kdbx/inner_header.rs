use std::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::reader::ByteReader;

const FIELD_END: u8 = 0;
const FIELD_STREAM_ID: u8 = 1;
const FIELD_STREAM_KEY: u8 = 2;
const FIELD_BINARY: u8 = 3;
const STREAM_CHACHA20: u32 = 3;
const BINARY_FLAG_PROTECTED: u8 = 0x01;
const MAX_BINARIES: usize = 100_000;

/// An attachment from the inner header binary pool. Entries reference it by
/// its position in the pool.
pub struct Binary {
    pub protected: bool,
    pub data: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binary")
            .field("protected", &self.protected)
            .field("length", &self.data.len())
            .finish()
    }
}

pub(crate) struct InnerHeader {
    pub(crate) stream: ProtectedStream,
    pub(crate) binaries: Vec<Binary>,
}

impl InnerHeader {
    /// Parses the inner header and returns it with the offset of the XML.
    pub(crate) fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let truncated = KdbxError::InvalidInnerHeader("truncated");
        let mut reader = ByteReader::new(data);
        let mut stream_id = None;
        let mut stream_key = None;
        let mut binaries = Vec::new();
        loop {
            let field = reader.u8(truncated)?;
            let length = usize::try_from(reader.u32(truncated)?).map_err(|_| truncated)?;
            let value = reader.take(length, truncated)?;
            match field {
                FIELD_END => break,
                FIELD_STREAM_ID => {
                    let id: [u8; 4] = value
                        .try_into()
                        .map_err(|_| KdbxError::InvalidInnerHeader("stream id"))?;
                    stream_id = Some(u32::from_le_bytes(id));
                }
                FIELD_STREAM_KEY => stream_key = Some(Zeroizing::new(value.to_vec())),
                FIELD_BINARY => {
                    let (&flags, content) = value
                        .split_first()
                        .ok_or(KdbxError::InvalidInnerHeader("binary"))?;
                    if binaries.len() == MAX_BINARIES {
                        return Err(KdbxError::LimitExceeded("attachments"));
                    }
                    binaries.push(Binary {
                        protected: flags & BINARY_FLAG_PROTECTED != 0,
                        data: Zeroizing::new(content.to_vec()),
                    });
                }
                _ => return Err(KdbxError::InvalidInnerHeader("unknown field")),
            }
        }

        if stream_id.ok_or(KdbxError::InvalidInnerHeader("missing stream id"))? != STREAM_CHACHA20 {
            return Err(KdbxError::InvalidInnerHeader("unsupported stream"));
        }
        let stream_key = stream_key.ok_or(KdbxError::InvalidInnerHeader("missing stream key"))?;
        let header = Self {
            stream: ProtectedStream::new(&stream_key),
            binaries,
        };
        Ok((header, reader.position()))
    }
}

/// Keystream for `Protected="True"` values. Values consume it in document
/// order, so they must be decrypted in the order they appear in the XML.
pub(crate) struct ProtectedStream(ChaCha20);

impl ProtectedStream {
    pub(crate) fn new(stream_key: &[u8]) -> Self {
        let digest = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(stream_key)));
        Self(ChaCha20::new(digest[..32].into(), digest[32..44].into()))
    }

    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data);
    }
}
