//! Changes to the document tree. New elements follow the layout KeePassXC
//! writes (`KdbxXmlWriter.cpp`), so entries created on the phone look like
//! entries created in KeePassXC.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use super::database::{decode_uuid, encode_uuid, Database, UUID_LENGTH};
use super::error::{KdbxError, Result};
use super::xml::{self, Element, Node};
use crate::random;

const STANDARD_KEYS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
/// KDBX 4 stores times as base64 of a little-endian i64 counting seconds from
/// 0001-01-01T00:00:00Z. This is where the Unix epoch falls on that scale.
const UNIX_EPOCH_SECONDS: i64 = 62_135_596_800;

impl Database {
    /// Adds an entry to the group with `group_uuid` and returns the entry's
    /// UUID. The five standard fields are always written, protected as the
    /// database's `MemoryProtection` settings say; other keys stay plain.
    /// `now` is in seconds since the Unix epoch.
    pub fn add_entry(
        &mut self,
        group_uuid: &[u8; UUID_LENGTH],
        fields: &[(&str, &str)],
        now: i64,
    ) -> Result<[u8; UUID_LENGTH]> {
        validate_keys(fields)?;
        let protected_keys = self.protected_standard_keys();
        let uuid = new_uuid()?;
        let entry = build_entry(&uuid, fields, &protected_keys, now);

        let group = group_mut(self.document_mut(), group_uuid).ok_or(KdbxError::UnknownGroup)?;
        // KeePassXC lists a group's entries before its subgroups.
        let position = group
            .children
            .iter()
            .rposition(|child| is_element(child, "Entry"))
            .map(|index| index + 1)
            .or_else(|| {
                group
                    .children
                    .iter()
                    .position(|child| is_element(child, "Group"))
            })
            .unwrap_or(group.children.len());
        group.children.insert(position, Node::Element(entry));
        Ok(uuid)
    }

    /// Standard keys that `Meta/MemoryProtection` protects, with KeePassXC's
    /// default (only the password) for missing settings.
    fn protected_standard_keys(&self) -> Vec<&'static str> {
        let settings = self.meta().and_then(|meta| meta.child("MemoryProtection"));
        STANDARD_KEYS
            .into_iter()
            .filter(|key| {
                settings
                    .and_then(|settings| settings.child(&format!("Protect{key}")))
                    .and_then(|setting| xml::parse_bool(&setting.text()))
                    .unwrap_or(*key == "Password")
            })
            .collect()
    }
}

fn validate_keys(fields: &[(&str, &str)]) -> Result<()> {
    for (index, (key, _)) in fields.iter().enumerate() {
        if key.is_empty() {
            return Err(KdbxError::InvalidEntry("empty field name"));
        }
        if fields[..index].iter().any(|(earlier, _)| earlier == key) {
            return Err(KdbxError::InvalidEntry("duplicate field"));
        }
    }
    Ok(())
}

fn build_entry(
    uuid: &[u8; UUID_LENGTH],
    fields: &[(&str, &str)],
    protected_keys: &[&str],
    now: i64,
) -> Element {
    let time = kdbx_time(now);
    let mut children = vec![
        text("UUID", &encode_uuid(uuid)),
        text("IconID", "0"),
        text("ForegroundColor", ""),
        text("BackgroundColor", ""),
        text("OverrideURL", ""),
        text("Tags", ""),
        element(
            "Times",
            vec![
                text("LastModificationTime", &time),
                text("CreationTime", &time),
                text("LastAccessTime", &time),
                text("ExpiryTime", &time),
                text("Expires", "False"),
                text("UsageCount", "0"),
                text("LocationChanged", &time),
            ],
        ),
    ];
    let value_of = |key: &str| {
        fields
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map_or("", |(_, value)| *value)
    };
    for key in STANDARD_KEYS {
        children.push(string_field(
            key,
            value_of(key),
            protected_keys.contains(&key),
        ));
    }
    for (key, value) in fields
        .iter()
        .filter(|(key, _)| !STANDARD_KEYS.contains(key))
    {
        children.push(string_field(key, value, false));
    }
    children.push(element(
        "AutoType",
        vec![
            text("Enabled", "True"),
            text("DataTransferObfuscation", "0"),
            text("DefaultSequence", ""),
        ],
    ));
    children.push(element("History", Vec::new()));
    element("Entry", children)
}

fn string_field(key: &str, value: &str, protected: bool) -> Element {
    let mut value_element = text("Value", value);
    if protected {
        value_element
            .attributes
            .push(("Protected".to_owned(), "True".to_owned()));
    }
    element("String", vec![text("Key", key), value_element])
}

fn element(name: &str, children: Vec<Element>) -> Element {
    Element {
        name: name.to_owned(),
        attributes: Vec::new(),
        children: children.into_iter().map(Node::Element).collect(),
    }
}

/// A leaf element; an empty value gives an empty element, as KeePassXC
/// writes it.
fn text(name: &str, value: &str) -> Element {
    let mut leaf = element(name, Vec::new());
    if !value.is_empty() {
        leaf.children
            .push(Node::Text(Zeroizing::new(value.to_owned())));
    }
    leaf
}

fn is_element(node: &Node, name: &str) -> bool {
    matches!(node, Node::Element(element) if element.name == name)
}

fn group_mut<'a>(document: &'a mut Element, uuid: &[u8; UUID_LENGTH]) -> Option<&'a mut Element> {
    let root = document.child_mut("Root")?.child_mut("Group")?;
    find_group_mut(root, uuid)
}

fn find_group_mut<'a>(group: &'a mut Element, uuid: &[u8; UUID_LENGTH]) -> Option<&'a mut Element> {
    if group.child("UUID").and_then(decode_uuid).as_ref() == Some(uuid) {
        return Some(group);
    }
    group
        .children
        .iter_mut()
        .filter_map(|child| match child {
            Node::Element(child) if child.name == "Group" => Some(child),
            _ => None,
        })
        .find_map(|child| find_group_mut(child, uuid))
}

/// A random (version 4) UUID, as KeePassXC's `QUuid::createUuid` makes them.
fn new_uuid() -> Result<[u8; UUID_LENGTH]> {
    let mut uuid = random::array::<UUID_LENGTH>()?;
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(uuid)
}

pub(crate) fn kdbx_time(unix_seconds: i64) -> String {
    STANDARD.encode(
        unix_seconds
            .saturating_add(UNIX_EPOCH_SECONDS)
            .to_le_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdbx_time_counts_from_year_one() {
        assert_eq!(kdbx_time(-UNIX_EPOCH_SECONDS), "AAAAAAAAAAA=");
        // 2026-01-01T10:00:00Z; checked against Python's datetime arithmetic.
        assert_eq!(kdbx_time(1_767_261_600), "oDzo4A4AAAA=");
    }

    #[test]
    fn rejects_empty_and_repeated_keys() {
        assert_eq!(
            validate_keys(&[("Title", "a"), ("", "b")]),
            Err(KdbxError::InvalidEntry("empty field name"))
        );
        assert_eq!(
            validate_keys(&[("Title", "a"), ("URL", "u"), ("Title", "b")]),
            Err(KdbxError::InvalidEntry("duplicate field"))
        );
        assert_eq!(validate_keys(&[("Title", "a"), ("PIN", "1")]), Ok(()));
    }

    #[test]
    fn new_uuids_are_version_4() {
        let uuid = new_uuid().unwrap();
        assert_eq!(uuid[6] >> 4, 4);
        assert_eq!(uuid[8] >> 6, 0b10);
        assert_ne!(new_uuid().unwrap(), uuid);
    }
}
