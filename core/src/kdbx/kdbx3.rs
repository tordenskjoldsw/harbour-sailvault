//! KDBX 3.x reader. A 3.x file is converted to the KDBX 4 model while it is
//! read, so it is saved as KDBX 4. Format details are verified against
//! KeePassXC (`src/format/Kdbx3Reader.cpp`, `KdbxReader.cpp`,
//! `KdbxXmlReader.cpp`, `src/streams/HashedBlockStream.cpp`) and
//! keepass.info.
//!
//! KDBX 3 authenticates less than KDBX 4: the header only through a SHA-256
//! in the XML, the payload only through unkeyed SHA-256 block hashes inside
//! the encryption. Wrong credentials show as wrong start bytes or padding.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::database::Database;
use super::error::{KdbxError, Result};
use super::header::{
    parse_cipher, parse_compression, Cipher, Compression, OuterHeader, MAX_HEADER_LENGTH,
    SIGNATURE_1, SIGNATURE_2_KDBX,
};
use super::inner_header::{Binary, InnerHeader, ProtectedStream, MAX_BINARIES};
use super::kdf::KdfParameters;
use super::key::{CompositeKey, KEY_LENGTH};
use super::payload::{self, MAX_PAYLOAD_LENGTH};
use super::reader::ByteReader;
use super::time::{kdbx_time, parse_iso_time};
use super::xml::{self, Element, Node};

pub(crate) const MAJOR_VERSION: u16 = 3;
const MAX_MINOR_VERSION: u16 = 1;

const FIELD_END: u8 = 0;
const FIELD_COMMENT: u8 = 1;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_COMPRESSION: u8 = 3;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_TRANSFORM_SEED: u8 = 5;
const FIELD_TRANSFORM_ROUNDS: u8 = 6;
const FIELD_ENCRYPTION_IV: u8 = 7;
const FIELD_PROTECTED_STREAM_KEY: u8 = 8;
const FIELD_STREAM_START_BYTES: u8 = 9;
const FIELD_INNER_STREAM_ID: u8 = 10;
// KeePassXC reads every KDBX 3 file with Salsa20, whatever the field says,
// and writes only this value.
const STREAM_SALSA20: u32 = 2;
const HASH_LENGTH: usize = 32;
// Decompressed attachments together, as much as the XML may hold.
const MAX_ATTACHMENT_BYTES: usize = 512 << 20;

// Elements holding a time; KDBX 3 writes them as ISO 8601 text.
const TIME_ELEMENTS: [&str; 13] = [
    "CreationTime",
    "LastModificationTime",
    "LastAccessTime",
    "ExpiryTime",
    "LocationChanged",
    "DeletionTime",
    "DatabaseNameChanged",
    "DatabaseDescriptionChanged",
    "DefaultUserNameChanged",
    "MasterKeyChanged",
    "RecycleBinChanged",
    "EntryTemplatesGroupChanged",
    "SettingsChanged",
];

struct Header {
    minor_version: u16,
    cipher: Cipher,
    compression: Compression,
    master_seed: [u8; 32],
    kdf: KdfParameters,
    encryption_iv: Vec<u8>,
    stream_key: Zeroizing<Vec<u8>>,
    start_bytes: [u8; HASH_LENGTH],
    length: usize,
}

impl Header {
    /// Every field is required: KeePassXC's defaults for missing ones only
    /// end in a wrong-credentials error.
    fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(data);
        let truncated = KdbxError::InvalidHeader("truncated");
        if reader.u32(KdbxError::NotKdbx)? != SIGNATURE_1
            || reader.u32(KdbxError::NotKdbx)? != SIGNATURE_2_KDBX
        {
            return Err(KdbxError::NotKdbx);
        }
        let minor = reader.u16(truncated)?;
        let major = reader.u16(truncated)?;
        if major != MAJOR_VERSION || minor > MAX_MINOR_VERSION {
            return Err(KdbxError::UnsupportedVersion { major, minor });
        }

        let mut cipher = None;
        let mut compression = None;
        let mut master_seed = None;
        let mut transform_seed = None;
        let mut rounds = None;
        let mut encryption_iv = None;
        let mut stream_key = None;
        let mut start_bytes = None;
        let mut stream_id = None;
        loop {
            let field = reader.u8(truncated)?;
            let length = usize::from(reader.u16(truncated)?);
            let value = reader.take(length, truncated)?;
            if reader.position() > MAX_HEADER_LENGTH {
                return Err(KdbxError::LimitExceeded("header length"));
            }
            let fixed = |name: &'static str| -> Result<[u8; HASH_LENGTH]> {
                value.try_into().map_err(|_| KdbxError::InvalidHeader(name))
            };
            match field {
                FIELD_END => break,
                FIELD_COMMENT => {}
                FIELD_CIPHER_ID => cipher = Some(parse_cipher(value)?),
                FIELD_COMPRESSION => compression = Some(parse_compression(value)?),
                FIELD_MASTER_SEED => master_seed = Some(fixed("master seed")?),
                FIELD_TRANSFORM_SEED => transform_seed = Some(fixed("transform seed")?),
                FIELD_TRANSFORM_ROUNDS => {
                    let bytes: [u8; 8] = value
                        .try_into()
                        .map_err(|_| KdbxError::InvalidHeader("transform rounds"))?;
                    rounds = Some(u64::from_le_bytes(bytes));
                }
                FIELD_ENCRYPTION_IV => encryption_iv = Some(value.to_vec()),
                FIELD_PROTECTED_STREAM_KEY => stream_key = Some(Zeroizing::new(value.to_vec())),
                FIELD_STREAM_START_BYTES => start_bytes = Some(fixed("stream start bytes")?),
                FIELD_INNER_STREAM_ID => {
                    let bytes: [u8; 4] = value
                        .try_into()
                        .map_err(|_| KdbxError::InvalidHeader("inner stream id"))?;
                    stream_id = Some(u32::from_le_bytes(bytes));
                }
                _ => return Err(KdbxError::InvalidHeader("unknown field")),
            }
        }

        let missing = KdbxError::InvalidHeader;
        let cipher = cipher.ok_or(missing("missing cipher"))?;
        let encryption_iv = encryption_iv.ok_or(missing("missing encryption IV"))?;
        if encryption_iv.len() != cipher.iv_length() {
            return Err(KdbxError::InvalidHeader("encryption IV length"));
        }
        if stream_id.ok_or(missing("missing inner stream id"))? != STREAM_SALSA20 {
            return Err(KdbxError::InvalidHeader("unsupported inner stream"));
        }
        Ok(Self {
            minor_version: minor,
            cipher,
            compression: compression.ok_or(missing("missing compression"))?,
            master_seed: master_seed.ok_or(missing("missing master seed"))?,
            kdf: KdfParameters::AesKdf {
                rounds: rounds.ok_or(missing("missing transform rounds"))?,
                seed: transform_seed.ok_or(missing("missing transform seed"))?,
            },
            encryption_iv,
            stream_key: stream_key.ok_or(missing("missing protected stream key"))?,
            start_bytes: start_bytes.ok_or(missing("missing stream start bytes"))?,
            length: reader.position(),
        })
    }
}

/// Unlocks a KDBX 3.x file and returns it as a KDBX 4.0 database with the
/// same cipher, compression and AES-KDF rounds. Runs the KDF, so it must
/// not run on the UI thread.
pub(super) fn open(data: &[u8], key: CompositeKey) -> Result<Database> {
    let header = Header::parse(data)?;
    let ciphertext = &data[header.length..];
    if ciphertext.len() > MAX_PAYLOAD_LENGTH {
        return Err(KdbxError::LimitExceeded("payload size"));
    }
    let transformed = header.kdf.transform(&key)?;
    let mut cipher_key = Zeroizing::new([0u8; KEY_LENGTH]);
    Sha256::new()
        .chain_update(header.master_seed)
        .chain_update(transformed.as_ref())
        .finalize_into(GenericArray::from_mut_slice(cipher_key.as_mut()));

    // Without a MAC, a wrong key surfaces as broken padding or start bytes.
    let plaintext = payload::decrypt_ciphertext(
        header.cipher,
        cipher_key.as_ref(),
        &header.encryption_iv,
        ciphertext.to_vec(),
    )
    .map_err(|error| match error {
        KdbxError::DecryptionFailed => KdbxError::InvalidCredentials,
        other => other,
    })?;
    if plaintext.get(..HASH_LENGTH) != Some(&header.start_bytes[..]) {
        return Err(KdbxError::InvalidCredentials);
    }
    let blocks = read_hashed_blocks(&plaintext[HASH_LENGTH..])?;
    drop(plaintext);
    let xml = match header.compression {
        Compression::None => blocks,
        Compression::Gzip => payload::gunzip(&blocks)?,
    };

    let mut stream = ProtectedStream::salsa20(&header.stream_key);
    let mut document = xml::parse_kdbx3(&xml, &mut stream)?;
    if document.name != "KeePassFile" {
        return Err(KdbxError::InvalidXml("unexpected root element"));
    }
    verify_header_hash(&mut document, &data[..header.length], header.minor_version)?;
    let binaries = move_attachments(&mut document)?;
    convert_times(&mut document);

    let kdbx4_header = OuterHeader::new(header.cipher, header.compression, header.kdf)?;
    Database::converted_from_kdbx3(kdbx4_header, InnerHeader { binaries }, document, key)
}

/// Joins the data of the hashed blocks: index, SHA-256 of the data, size,
/// data; an empty block with a zero hash ends the stream.
fn read_hashed_blocks(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let corrupted = KdbxError::PayloadCorrupted;
    let mut reader = ByteReader::new(data);
    let mut joined = Zeroizing::new(Vec::with_capacity(data.len()));
    for expected_index in 0..=u32::MAX {
        if reader.u32(corrupted)? != expected_index {
            return Err(corrupted);
        }
        let hash: [u8; HASH_LENGTH] = reader.array(corrupted)?;
        let size = usize::try_from(reader.i32(corrupted)?).map_err(|_| corrupted)?;
        if size == 0 {
            return if hash == [0; HASH_LENGTH] {
                Ok(joined)
            } else {
                Err(corrupted)
            };
        }
        let block = reader.take(size, corrupted)?;
        if Sha256::digest(block).as_slice() != hash {
            return Err(corrupted);
        }
        joined.extend_from_slice(block);
    }
    Err(corrupted)
}

/// Checks `Meta/HeaderHash`, the only protection of a KDBX 3 header, and
/// removes it. KeePass writes it since KDBX 3.1, so a 3.1 file must have it.
fn verify_header_hash(document: &mut Element, header: &[u8], minor_version: u16) -> Result<()> {
    let meta = document
        .child_mut("Meta")
        .ok_or(KdbxError::InvalidXml("missing metadata"))?;
    let stored = take_children(meta, "HeaderHash");
    match stored.as_slice() {
        [] if minor_version == 0 => Ok(()),
        [hash] => {
            let stored = STANDARD
                .decode(hash.text().trim())
                .map_err(|_| KdbxError::HeaderCorrupted)?;
            if stored.as_slice() == Sha256::digest(header).as_slice() {
                Ok(())
            } else {
                Err(KdbxError::HeaderCorrupted)
            }
        }
        _ => Err(KdbxError::HeaderCorrupted),
    }
}

/// Moves the attachments from `Meta/Binaries` and from inline entry values
/// into the KDBX 4 pool and points the entries' `Ref` attributes at it. A
/// reference to a missing attachment is dropped, as KeePassXC drops it.
fn move_attachments(document: &mut Element) -> Result<Vec<Binary>> {
    let mut pool = AttachmentPool::default();
    let mut ids = HashMap::new();
    if let Some(meta) = document.child_mut("Meta") {
        for binaries in take_children(meta, "Binaries") {
            for binary in binaries.children_named("Binary") {
                let id = binary
                    .attribute("ID")
                    .ok_or(KdbxError::InvalidXml("attachment id"))?;
                let index = pool.add(binary)?;
                if ids.insert(id.to_owned(), index).is_some() {
                    return Err(KdbxError::InvalidXml("duplicate attachment id"));
                }
            }
        }
    }
    let root = document
        .child_mut("Root")
        .ok_or(KdbxError::InvalidXml("missing root group"))?;
    rewrite_references(root, &ids, &mut pool)?;
    Ok(pool.binaries)
}

#[derive(Default)]
struct AttachmentPool {
    binaries: Vec<Binary>,
    total_bytes: usize,
}

impl AttachmentPool {
    /// Adds the base64 content of `element`, gunzipped when it says
    /// `Compressed="True"`, and returns its pool index. KeePassXC writes
    /// every KDBX 4 attachment as protected.
    fn add(&mut self, element: &Element) -> Result<usize> {
        if self.binaries.len() == MAX_BINARIES {
            return Err(KdbxError::LimitExceeded("attachments"));
        }
        let decoded = Zeroizing::new(
            STANDARD
                .decode(element.text().trim())
                .map_err(|_| KdbxError::InvalidXml("attachment"))?,
        );
        let data = if element.attribute("Compressed").and_then(xml::parse_bool) == Some(true) {
            payload::gunzip(&decoded)?
        } else {
            decoded
        };
        self.total_bytes = self
            .total_bytes
            .checked_add(data.len())
            .filter(|&total| total <= MAX_ATTACHMENT_BYTES)
            .ok_or(KdbxError::LimitExceeded("attachments"))?;
        self.binaries.push(Binary {
            protected: true,
            data,
        });
        Ok(self.binaries.len() - 1)
    }
}

/// Visits every entry, history items included, and rewrites its attachment
/// references.
fn rewrite_references(
    element: &mut Element,
    ids: &HashMap<String, usize>,
    pool: &mut AttachmentPool,
) -> Result<()> {
    if element.name == "Entry" {
        let mut result = Ok(());
        element.children.retain_mut(|child| match child {
            Node::Element(binary) if binary.name == "Binary" && result.is_ok() => {
                match rewrite_reference(binary, ids, pool) {
                    Ok(keep) => keep,
                    Err(error) => {
                        result = Err(error);
                        true
                    }
                }
            }
            _ => true,
        });
        result?;
    }
    for child in &mut element.children {
        if let Node::Element(child) = child {
            rewrite_references(child, ids, pool)?;
        }
    }
    Ok(())
}

/// Points one entry attachment at the pool. Returns false for a reference
/// to a missing attachment.
fn rewrite_reference(
    binary: &mut Element,
    ids: &HashMap<String, usize>,
    pool: &mut AttachmentPool,
) -> Result<bool> {
    let Some(value) = binary.child_mut("Value") else {
        return Ok(true);
    };
    let index = match value.attribute("Ref") {
        Some(reference) => match ids.get(reference) {
            Some(&index) => index,
            None => return Ok(false),
        },
        // Content stored in the entry itself, as older files do.
        None => pool.add(value)?,
    };
    *value = Element {
        name: "Value".to_owned(),
        attributes: vec![("Ref".to_owned(), index.to_string())],
        children: Vec::new(),
    };
    Ok(true)
}

/// Rewrites ISO 8601 times as KDBX 4 times. A time that is not valid ISO
/// 8601 with a zone stays as it is; KeePassXC reads both forms.
fn convert_times(element: &mut Element) {
    if TIME_ELEMENTS.contains(&element.name.as_str()) && element.elements().next().is_none() {
        if let Some(seconds) = parse_iso_time(&element.text()) {
            element.children = vec![Node::Text(Zeroizing::new(kdbx_time(seconds)))];
        }
        return;
    }
    for child in &mut element.children {
        if let Node::Element(child) = child {
            convert_times(child);
        }
    }
}

fn take_children(element: &mut Element, name: &str) -> Vec<Element> {
    let mut taken = Vec::new();
    element.children.retain_mut(|child| match child {
        Node::Element(found) if found.name == name => {
            taken.push(std::mem::replace(
                found,
                Element {
                    name: String::new(),
                    attributes: Vec::new(),
                    children: Vec::new(),
                },
            ));
            false
        }
        _ => true,
    });
    taken
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(index: u32, data: &[u8]) -> Vec<u8> {
        let mut out = index.to_le_bytes().to_vec();
        if data.is_empty() {
            out.extend_from_slice(&[0; HASH_LENGTH]);
        } else {
            out.extend_from_slice(&Sha256::digest(data));
        }
        out.extend_from_slice(&i32::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn hashed_blocks_join_until_the_empty_block() {
        let stream = [block(0, b"first "), block(1, b"second"), block(2, b"")].concat();
        assert_eq!(
            read_hashed_blocks(&stream).unwrap().as_slice(),
            b"first second"
        );
    }

    #[test]
    fn hashed_blocks_with_wrong_index_hash_or_end_are_rejected() {
        let wrong_index = [block(1, b"data"), block(2, b"")].concat();
        let mut wrong_hash = [block(0, b"data"), block(1, b"")].concat();
        wrong_hash[4] ^= 1;
        let mut nonzero_end = [block(0, b"data"), block(1, b"")].concat();
        let end_hash = 4 + HASH_LENGTH + 4 + 4 + 4;
        nonzero_end[end_hash] = 1;
        let unterminated = block(0, b"data");
        let mut negative = block(0, b"data");
        negative[4 + HASH_LENGTH..4 + HASH_LENGTH + 4].copy_from_slice(&(-1i32).to_le_bytes());
        for stream in [wrong_index, wrong_hash, nonzero_end, unterminated, negative] {
            assert_eq!(
                read_hashed_blocks(&stream).map(|_| ()),
                Err(KdbxError::PayloadCorrupted)
            );
        }
    }

    fn header_bytes(minor: u16, fields: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = SIGNATURE_1.to_le_bytes().to_vec();
        out.extend_from_slice(&SIGNATURE_2_KDBX.to_le_bytes());
        out.extend_from_slice(&minor.to_le_bytes());
        out.extend_from_slice(&MAJOR_VERSION.to_le_bytes());
        for (id, value) in fields {
            out.push(*id);
            out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    const AES256: [u8; 16] = [
        0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a,
        0xff,
    ];

    fn fields(stream_id: u32) -> Vec<(u8, Vec<u8>)> {
        vec![
            (FIELD_CIPHER_ID, AES256.to_vec()),
            (FIELD_COMPRESSION, 1u32.to_le_bytes().to_vec()),
            (FIELD_MASTER_SEED, vec![1; 32]),
            (FIELD_TRANSFORM_SEED, vec![2; 32]),
            (FIELD_TRANSFORM_ROUNDS, 1000u64.to_le_bytes().to_vec()),
            (FIELD_ENCRYPTION_IV, vec![3; 16]),
            (FIELD_PROTECTED_STREAM_KEY, vec![4; 32]),
            (FIELD_STREAM_START_BYTES, vec![5; 32]),
            (FIELD_INNER_STREAM_ID, stream_id.to_le_bytes().to_vec()),
            (FIELD_END, b"\r\n\r\n".to_vec()),
        ]
    }

    fn parse(minor: u16, fields: &[(u8, Vec<u8>)]) -> Result<Header> {
        let borrowed: Vec<(u8, &[u8])> = fields.iter().map(|(id, v)| (*id, v.as_slice())).collect();
        Header::parse(&header_bytes(minor, &borrowed))
    }

    #[test]
    fn complete_header_parses() {
        let header = parse(1, &fields(STREAM_SALSA20)).unwrap();
        assert_eq!(header.cipher, Cipher::Aes256);
        assert_eq!(header.compression, Compression::Gzip);
        assert_eq!(
            header.kdf,
            KdfParameters::AesKdf {
                rounds: 1000,
                seed: [2; 32]
            }
        );
        assert_eq!(
            header.length,
            header_bytes(1, &[]).len() + fields(2).iter().map(|(_, v)| 3 + v.len()).sum::<usize>()
        );
    }

    #[test]
    fn incomplete_or_unsupported_headers_are_rejected() {
        assert_eq!(
            parse(1, &fields(3)).map(|_| ()),
            Err(KdbxError::InvalidHeader("unsupported inner stream"))
        );
        assert_eq!(
            parse(2, &fields(STREAM_SALSA20)).map(|_| ()),
            Err(KdbxError::UnsupportedVersion { major: 3, minor: 2 })
        );
        let mut without_start_bytes = fields(STREAM_SALSA20);
        without_start_bytes.retain(|(id, _)| *id != FIELD_STREAM_START_BYTES);
        assert_eq!(
            parse(1, &without_start_bytes).map(|_| ()),
            Err(KdbxError::InvalidHeader("missing stream start bytes"))
        );
        let mut short_seed = fields(STREAM_SALSA20);
        short_seed[2].1.pop();
        assert_eq!(
            parse(1, &short_seed).map(|_| ()),
            Err(KdbxError::InvalidHeader("master seed"))
        );
        let mut kdbx4_field = fields(STREAM_SALSA20);
        kdbx4_field.insert(0, (11, vec![0]));
        assert_eq!(
            parse(1, &kdbx4_field).map(|_| ()),
            Err(KdbxError::InvalidHeader("unknown field"))
        );
    }

    fn document(xml: &str) -> Element {
        xml::parse_kdbx3(xml.as_bytes(), &mut ProtectedStream::salsa20(b"key")).unwrap()
    }

    #[test]
    fn attachments_move_to_the_pool_and_references_follow() {
        let mut document = document(
            "<KeePassFile><Meta><Binaries>\
             <Binary ID=\"7\">YQ==</Binary><Binary ID=\"3\">Yg==</Binary>\
             </Binaries></Meta><Root><Group><Entry>\
             <Binary><Key>b</Key><Value Ref=\"3\"/></Binary>\
             <Binary><Key>gone</Key><Value Ref=\"9\"/></Binary>\
             <Binary><Key>inline</Key><Value>Yw==</Value></Binary>\
             <History><Entry><Binary><Key>a</Key><Value Ref=\"7\"/></Binary></Entry></History>\
             </Entry></Group></Root></KeePassFile>",
        );
        let pool = move_attachments(&mut document).unwrap();
        let data: Vec<&[u8]> = pool.iter().map(|binary| binary.data.as_slice()).collect();
        assert_eq!(data, [&b"a"[..], b"b", b"c"]);
        assert!(document.child("Meta").unwrap().child("Binaries").is_none());

        let entry = document
            .child("Root")
            .unwrap()
            .child("Group")
            .unwrap()
            .child("Entry")
            .unwrap();
        let references: Vec<(String, String)> = entry
            .children_named("Binary")
            .map(|binary| {
                (
                    binary.child("Key").unwrap().text().to_string(),
                    binary
                        .child("Value")
                        .unwrap()
                        .attribute("Ref")
                        .unwrap()
                        .to_owned(),
                )
            })
            .collect();
        assert_eq!(
            references,
            [
                ("b".to_owned(), "1".to_owned()),
                ("inline".to_owned(), "2".to_owned())
            ]
        );
        let history_reference = entry
            .child("History")
            .unwrap()
            .child("Entry")
            .unwrap()
            .child("Binary")
            .unwrap()
            .child("Value")
            .unwrap()
            .attribute("Ref");
        assert_eq!(history_reference, Some("0"));
    }

    #[test]
    fn duplicate_attachment_ids_are_rejected() {
        let mut document = document(
            "<KeePassFile><Meta><Binaries><Binary ID=\"0\">YQ==</Binary>\
             <Binary ID=\"0\">Yg==</Binary></Binaries></Meta><Root/></KeePassFile>",
        );
        assert_eq!(
            move_attachments(&mut document).map(|_| ()),
            Err(KdbxError::InvalidXml("duplicate attachment id"))
        );
    }

    #[test]
    fn protected_attachments_keep_their_bytes() {
        let plaintext = [0xffu8, 0x00, 0xfe];
        let mut ciphertext = plaintext;
        ProtectedStream::salsa20(b"key").apply(&mut ciphertext);
        let mut document = document(&format!(
            "<KeePassFile><Meta><Binaries><Binary ID=\"0\" Protected=\"True\">{}</Binary>\
             </Binaries></Meta><Root/></KeePassFile>",
            STANDARD.encode(ciphertext)
        ));
        let pool = move_attachments(&mut document).unwrap();
        assert_eq!(pool[0].data.as_slice(), plaintext);
    }

    #[test]
    fn iso_times_become_kdbx4_times_and_others_stay() {
        let mut document = document(
            "<KeePassFile><Times><CreationTime>2026-01-01T10:00:00Z</CreationTime>\
             <ExpiryTime>2026-01-01T10:00:00</ExpiryTime>\
             <Name>2026-01-01T10:00:00Z</Name></Times></KeePassFile>",
        );
        convert_times(&mut document);
        let times = document.child("Times").unwrap();
        assert_eq!(*times.child("CreationTime").unwrap().text(), "oDzo4A4AAAA=");
        assert_eq!(
            *times.child("ExpiryTime").unwrap().text(),
            "2026-01-01T10:00:00"
        );
        assert_eq!(*times.child("Name").unwrap().text(), "2026-01-01T10:00:00Z");
    }
}
