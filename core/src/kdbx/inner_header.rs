use std::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::write_field;
use super::reader::ByteReader;

const FIELD_END: u8 = 0;
const FIELD_STREAM_ID: u8 = 1;
const FIELD_STREAM_KEY: u8 = 2;
const FIELD_BINARY: u8 = 3;
const STREAM_CHACHA20: u32 = 3;
const BINARY_FLAG_PROTECTED: u8 = 0x01;
const MAX_BINARIES: usize = 100_000;
pub(crate) const STREAM_KEY_LENGTH: usize = 64;

/// An attachment from the inner header binary pool. Entries reference it by
/// its position in the pool.
#[derive(PartialEq, Eq)]
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

#[derive(Default)]
pub(crate) struct InnerHeader {
    pub(crate) binaries: Vec<Binary>,
}

impl InnerHeader {
    /// Parses the inner header. Returns it with the keystream for protected
    /// values, which the caller drops after parsing the XML, and the offset
    /// of the XML.
    pub(crate) fn parse(data: &[u8]) -> Result<(Self, ProtectedStream, usize)> {
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
        Ok((
            Self { binaries },
            ProtectedStream::new(&stream_key),
            reader.position(),
        ))
    }

    /// Serializes the inner header with `stream_key` for the protected values
    /// of the XML that follows it. The binary pool keeps its order, so the
    /// `Ref` attributes in the XML stay valid.
    pub(crate) fn serialize(
        &self,
        stream_key: &[u8; STREAM_KEY_LENGTH],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        write_field(out, FIELD_STREAM_ID, &STREAM_CHACHA20.to_le_bytes())?;
        write_field(out, FIELD_STREAM_KEY, stream_key)?;
        for binary in &self.binaries {
            let length = u32::try_from(binary.data.len() + 1)
                .map_err(|_| KdbxError::LimitExceeded("attachment size"))?;
            out.push(FIELD_BINARY);
            out.extend_from_slice(&length.to_le_bytes());
            out.push(if binary.protected {
                BINARY_FLAG_PROTECTED
            } else {
                0
            });
            out.extend_from_slice(&binary.data);
        }
        write_field(out, FIELD_END, &[])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_inner_header_parses_back() {
        let original = InnerHeader {
            binaries: vec![
                Binary {
                    protected: true,
                    data: Zeroizing::new(b"attachment".to_vec()),
                },
                Binary {
                    protected: false,
                    data: Zeroizing::new(Vec::new()),
                },
            ],
        };
        let key = [9u8; STREAM_KEY_LENGTH];
        let mut bytes = Vec::new();
        original.serialize(&key, &mut bytes).unwrap();
        bytes.extend_from_slice(b"<xml/>");

        let (parsed, mut stream, offset) = InnerHeader::parse(&bytes).unwrap();
        assert_eq!(&bytes[offset..], b"<xml/>");
        assert!(parsed.binaries == original.binaries);
        let mut probe = [0u8; 8];
        stream.apply(&mut probe);
        let mut expected = [0u8; 8];
        ProtectedStream::new(&key).apply(&mut expected);
        assert_eq!(probe, expected);
    }
}
