use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::error::{KdbxError, Result};
use super::xml::predefined_entity;

pub const KEY_LENGTH: usize = 32;

/// SHA-256 over the hashed password followed by the key file key, as in
/// KeePassXC's `CompositeKey::rawKey`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CompositeKey([u8; KEY_LENGTH]);

impl CompositeKey {
    pub fn new(password: Option<&[u8]>, key_file: Option<&[u8]>) -> Result<Self> {
        if password.is_none() && key_file.is_none() {
            return Err(KdbxError::InvalidCredentials);
        }
        let mut hasher = Sha256::new();
        if let Some(password) = password {
            hasher.update(Zeroizing::new(<[u8; KEY_LENGTH]>::from(Sha256::digest(
                password,
            ))));
        }
        if let Some(key_file) = key_file {
            hasher.update(key_file_key(key_file)?);
        }
        Ok(Self(hasher.finalize().into()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompositeKey(..)")
    }
}

/// Mirrors KeePassXC's `FileKey::load`: XML key file v1/v2, then a raw
/// 32-byte file, then 64 hex characters, otherwise the SHA-256 of the file.
fn key_file_key(content: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    if content.is_empty() {
        return Err(KdbxError::InvalidKeyFile);
    }
    if let Some(key) = xml_key_file(content)? {
        return Ok(key);
    }
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    if content.len() == KEY_LENGTH {
        key.copy_from_slice(content);
    } else if content.len() == 2 * KEY_LENGTH && content.iter().all(u8::is_ascii_hexdigit) {
        let decoded = Zeroizing::new(decode_hex(content).ok_or(KdbxError::InvalidKeyFile)?);
        key.copy_from_slice(&decoded);
    } else {
        key.copy_from_slice(&Sha256::digest(content));
    }
    Ok(key)
}

/// Returns `None` when the content is not a KeePass XML key file, so the
/// caller falls back to the legacy formats, and an error when it is one but
/// is invalid.
fn xml_key_file(content: &[u8]) -> Result<Option<Zeroizing<[u8; KEY_LENGTH]>>> {
    let mut reader = Reader::from_reader(content);
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut version = None;
    let mut hash = None;
    let mut data = Zeroizing::new(String::new());
    let mut root_seen = false;

    loop {
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(_) => return Ok(None),
        };
        match event {
            Event::Start(element) => {
                let name = element.local_name().as_ref().to_vec();
                if !root_seen {
                    if name != b"KeyFile" {
                        return Ok(None);
                    }
                    root_seen = true;
                }
                if path.len() == 2 && path[1] == b"Key" && name == b"Data" {
                    hash = element
                        .attributes()
                        .flatten()
                        .find(|attribute| attribute.key.local_name().as_ref() == b"Hash")
                        .and_then(|attribute| attribute.unescape_value().ok())
                        .map(|value| value.into_owned());
                }
                path.push(name);
            }
            Event::Empty(_) if !root_seen => return Ok(None),
            Event::Text(text) => {
                let Ok(text) = text.xml10_content() else {
                    return Ok(None);
                };
                append_text(&path, &text, &mut version, &mut data);
            }
            // Entity and character references arrive as separate events.
            Event::GeneralRef(reference) => {
                let character = match reference.resolve_char_ref() {
                    Ok(Some(character)) => character,
                    Ok(None) => match predefined_entity(&reference) {
                        Ok(character) => character,
                        Err(_) => return Ok(None),
                    },
                    Err(_) => return Ok(None),
                };
                append_text(
                    &path,
                    character.encode_utf8(&mut [0u8; 4]),
                    &mut version,
                    &mut data,
                );
            }
            Event::End(_) => {
                path.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !root_seen || data.is_empty() {
        return Ok(None);
    }
    let version = version.map(|version| version.trim().to_owned());
    let decoded = match version.as_deref() {
        Some(version) if version.starts_with("1.0") => Zeroizing::new(
            STANDARD
                .decode(data.as_bytes())
                .map_err(|_| KdbxError::InvalidKeyFile)?,
        ),
        Some("2.0") => {
            let decoded =
                Zeroizing::new(decode_hex(data.as_bytes()).ok_or(KdbxError::InvalidKeyFile)?);
            let expected = hash
                .as_deref()
                .and_then(|hash| decode_hex(hash.as_bytes()))
                .ok_or(KdbxError::InvalidKeyFile)?;
            if Sha256::digest(&*decoded)[..4] != expected[..] {
                return Err(KdbxError::InvalidKeyFile);
            }
            decoded
        }
        _ => return Err(KdbxError::InvalidKeyFile),
    };
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    let length = decoded.len().min(KEY_LENGTH);
    key[..length].copy_from_slice(&decoded[..length]);
    Ok(Some(key))
}

fn append_text(path: &[Vec<u8>], text: &str, version: &mut Option<String>, data: &mut String) {
    match path
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [b"KeyFile", b"Meta", b"Version"] => version.get_or_insert_with(String::new).push_str(text),
        [b"KeyFile", b"Key", b"Data"] => data.extend(text.chars().filter(|c| !c.is_whitespace())),
        _ => {}
    }
}

fn decode_hex(hex: &[u8]) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    hex.chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(content: &[u8]) -> [u8; KEY_LENGTH] {
        *key_file_key(content).unwrap()
    }

    #[test]
    fn raw_and_hex_key_files() {
        let raw: Vec<u8> = (0..32).collect();
        assert_eq!(key(&raw).to_vec(), raw);
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(key(hex.as_bytes()).to_vec(), raw);
    }

    #[test]
    fn other_files_are_hashed() {
        let content = b"any other file content";
        assert_eq!(key(content), <[u8; 32]>::from(Sha256::digest(content)));
        let foreign_xml = b"<?xml version=\"1.0\"?><Other><Key/></Other>";
        assert_eq!(
            key(foreign_xml),
            <[u8; 32]>::from(Sha256::digest(foreign_xml))
        );
    }

    #[test]
    fn xml_v1_key_file() {
        let raw = [7u8; 32];
        let xml = format!(
            "<?xml version=\"1.0\"?><KeyFile><Meta><Version>1.00</Version></Meta>\
             <Key><Data>{}</Data></Key></KeyFile>",
            STANDARD.encode(raw)
        );
        assert_eq!(key(xml.as_bytes()), raw);
    }

    #[test]
    fn xml_v2_key_file_checks_its_hash() {
        let raw = [9u8; 32];
        let hex: String = raw.iter().map(|b| format!("{b:02X}")).collect();
        let hash: String = Sha256::digest(raw)[..4]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        let xml = |hash: &str| {
            format!(
                "<?xml version=\"1.0\"?><KeyFile><Meta><Version>2.0</Version></Meta>\
                 <Key><Data Hash=\"{hash}\">{} {}</Data></Key></KeyFile>",
                &hex[..32],
                &hex[32..]
            )
        };
        assert_eq!(key(xml(&hash).as_bytes()), raw);
        assert_eq!(
            key_file_key(xml("00000000").as_bytes()).map(|_| ()),
            Err(KdbxError::InvalidKeyFile)
        );
    }

    #[test]
    fn xml_key_file_resolves_character_references() {
        let raw = [7u8; 32];
        let xml = format!(
            "<?xml version=\"1.0\"?><KeyFile><Meta><Version>1&#46;0</Version></Meta>\
             <Key><Data>{}</Data></Key></KeyFile>",
            STANDARD.encode(raw).replace('=', "&#61;")
        );
        assert_eq!(key(xml.as_bytes()), raw);
    }

    #[test]
    fn empty_password_differs_from_no_password() {
        let key_file = [3u8; 32];
        let none = CompositeKey::new(None, Some(&key_file)).unwrap();
        let empty = CompositeKey::new(Some(b""), Some(&key_file)).unwrap();
        assert_ne!(none.as_bytes(), empty.as_bytes());
    }

    #[test]
    fn rejects_empty_key_file_and_missing_credentials() {
        assert_eq!(
            key_file_key(b"").map(|_| ()),
            Err(KdbxError::InvalidKeyFile)
        );
        assert!(CompositeKey::new(None, None).is_err());
    }
}
