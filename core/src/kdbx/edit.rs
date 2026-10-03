//! Changes to the document tree. New elements follow the layout KeePassXC
//! writes (`KdbxXmlWriter.cpp`), and edits follow its `Entry.cpp` and
//! `Database.cpp`, so files changed on the phone look like files changed in
//! KeePassXC.

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
// KeePassXC's defaults for Meta/HistoryMaxItems and Meta/HistoryMaxSize.
const DEFAULT_HISTORY_MAX_ITEMS: i64 = 10;
const DEFAULT_HISTORY_MAX_SIZE: i64 = 6 * 1024 * 1024;
const RECYCLE_BIN_ICON: &str = "43";
const NO_UUID: [u8; UUID_LENGTH] = [0; UUID_LENGTH];
// Entry children that KeePassXC writes after the String elements.
const AFTER_STRINGS: [&str; 4] = ["Binary", "AutoType", "CustomData", "History"];

/// `None` means unlimited (-1 in the file).
struct HistoryLimits {
    max_items: Option<usize>,
    max_size: Option<usize>,
}

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
        insert_entry(group, entry);
        Ok(uuid)
    }

    /// Sets fields of the entry with `uuid`. A changed entry gets its
    /// previous state as a history item, new modification and access times,
    /// and a history trimmed to the database's limits, as in KeePassXC's
    /// `Entry::endUpdate`. Returns whether anything changed.
    pub fn update_entry(
        &mut self,
        uuid: &[u8; UUID_LENGTH],
        fields: &[(&str, &str)],
        now: i64,
    ) -> Result<bool> {
        validate_keys(fields)?;
        let protected_keys = self.protected_standard_keys();
        let limits = self.history_limits();
        let attachment_sizes: Vec<usize> = self
            .binaries()
            .iter()
            .map(|binary| binary.data.len())
            .collect();
        let path = entry_path(self.document(), uuid).ok_or(KdbxError::UnknownEntry)?;
        let entry = descend_mut(self.document_mut(), &path).ok_or(KdbxError::UnknownEntry)?;

        let unchanged = fields.iter().all(|(key, value)| {
            field_value(entry, key).map_or(value.is_empty(), |current| *current == *value)
        });
        if unchanged {
            return Ok(false);
        }
        let mut previous = entry.clone();
        previous
            .children
            .retain(|child| !is_element(child, "History"));
        for (key, value) in fields {
            set_field(entry, key, value, protected_keys.contains(key));
        }
        let time = kdbx_time(now);
        set_time(entry, "LastModificationTime", &time);
        set_time(entry, "LastAccessTime", &time);
        child_or_append(entry, "History")
            .children
            .push(Node::Element(previous));
        truncate_history(entry, &limits, &attachment_sizes);
        Ok(true)
    }

    /// Moves the entry with `uuid` to the recycle bin. An entry that is
    /// already there, or any entry while the recycle bin is disabled, is
    /// removed for good and recorded under `DeletedObjects`. Returns whether
    /// it was removed for good.
    pub fn delete_entry(&mut self, uuid: &[u8; UUID_LENGTH], now: i64) -> Result<bool> {
        let path = entry_path(self.document(), uuid).ok_or(KdbxError::UnknownEntry)?;
        if self.deletes_permanently_at(&path) {
            remove_at(self.document_mut(), &path).ok_or(KdbxError::UnknownEntry)?;
            let deleted = child_or_append(root_mut(self.document_mut())?, "DeletedObjects");
            deleted.children.push(Node::Element(element(
                "DeletedObject",
                vec![
                    text("UUID", &encode_uuid(uuid)),
                    text("DeletionTime", &kdbx_time(now)),
                ],
            )));
            return Ok(true);
        }

        let bin = match self.recycle_bin() {
            Some(bin) => bin,
            None => self.create_recycle_bin(now)?,
        };
        let previous_group = groups_on_path(self.document(), &path)
            .last()
            .and_then(|group| group.child("UUID"))
            .and_then(decode_uuid);
        let minor_version = self.header().minor_version;
        let mut entry = remove_at(self.document_mut(), &path).ok_or(KdbxError::UnknownEntry)?;
        set_time(&mut entry, "LocationChanged", &kdbx_time(now));
        if let (true, Some(previous_group)) = (minor_version >= 1, previous_group) {
            set_previous_parent_group(&mut entry, &previous_group);
        }
        let bin_group = group_mut(self.document_mut(), &bin).ok_or(KdbxError::UnknownGroup)?;
        insert_entry(bin_group, entry);
        Ok(false)
    }

    /// Whether `delete_entry` would remove the entry for good instead of
    /// moving it to the recycle bin.
    pub fn deletes_permanently(&self, uuid: &[u8; UUID_LENGTH]) -> Result<bool> {
        let path = entry_path(self.document(), uuid).ok_or(KdbxError::UnknownEntry)?;
        Ok(self.deletes_permanently_at(&path))
    }

    fn deletes_permanently_at(&self, path: &[usize]) -> bool {
        match self.recycle_bin() {
            None => !self.recycle_bin_enabled(),
            Some(bin) => groups_on_path(self.document(), path)
                .iter()
                .any(|group| group.child("UUID").and_then(decode_uuid) == Some(bin)),
        }
    }

    /// Creates the recycle bin group as KeePassXC's `Database::createRecycleBin`
    /// does and points `Meta` at it.
    fn create_recycle_bin(&mut self, now: i64) -> Result<[u8; UUID_LENGTH]> {
        let uuid = new_uuid()?;
        let time = kdbx_time(now);
        let group = element(
            "Group",
            vec![
                text("UUID", &encode_uuid(&uuid)),
                text("Name", "Recycle Bin"),
                text("Notes", ""),
                text("IconID", RECYCLE_BIN_ICON),
                times(&time),
                text("IsExpanded", "True"),
                text("DefaultAutoTypeSequence", ""),
                text("EnableAutoType", "false"),
                text("EnableSearching", "false"),
                text("LastTopVisibleEntry", &encode_uuid(&NO_UUID)),
            ],
        );
        root_group_mut(self.document_mut())?
            .children
            .push(Node::Element(group));
        let meta = self
            .document_mut()
            .child_mut("Meta")
            .ok_or(KdbxError::InvalidXml("missing Meta"))?;
        set_child_text(meta, "RecycleBinUUID", &encode_uuid(&uuid));
        set_child_text(meta, "RecycleBinChanged", &time);
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

    fn history_limits(&self) -> HistoryLimits {
        let setting = |name: &str, default: i64| {
            let value = self
                .meta()
                .and_then(|meta| meta.child(name))
                .and_then(|setting| setting.text().trim().parse::<i64>().ok())
                .unwrap_or(default);
            usize::try_from(value).ok()
        };
        HistoryLimits {
            max_items: setting("HistoryMaxItems", DEFAULT_HISTORY_MAX_ITEMS),
            max_size: setting("HistoryMaxSize", DEFAULT_HISTORY_MAX_SIZE),
        }
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
        times(&time),
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

fn times(time: &str) -> Element {
    element(
        "Times",
        vec![
            text("LastModificationTime", time),
            text("CreationTime", time),
            text("LastAccessTime", time),
            text("ExpiryTime", time),
            text("Expires", "False"),
            text("UsageCount", "0"),
            text("LocationChanged", time),
        ],
    )
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

/// The current value of a field: the last `String` with that key, as
/// `Entry::fields` resolves repeats.
fn field_value(entry: &Element, key: &str) -> Option<Zeroizing<String>> {
    entry
        .children_named("String")
        .filter(|string| string.child("Key").is_some_and(|k| *k.text() == *key))
        .last()
        .and_then(|string| string.child("Value"))
        .map(Element::text)
}

/// Replaces the value of an existing field, keeping its `Protected`
/// attribute, or appends a new `String` where KeePassXC writes them.
fn set_field(entry: &mut Element, key: &str, value: &str, protected: bool) {
    let existing = entry
        .children
        .iter_mut()
        .filter_map(|child| match child {
            Node::Element(string) if string.name == "String" => Some(string),
            _ => None,
        })
        .filter(|string| string.child("Key").is_some_and(|k| *k.text() == *key))
        .last()
        .and_then(|string| string.child_mut("Value"));
    match existing {
        Some(value_element) => replace_text(value_element, value),
        None => {
            let position = entry
                .children
                .iter()
                .rposition(|child| is_element(child, "String"))
                .map(|index| index + 1)
                .or_else(|| {
                    entry
                        .children
                        .iter()
                        .position(|child| AFTER_STRINGS.iter().any(|name| is_element(child, name)))
                })
                .unwrap_or(entry.children.len());
            entry
                .children
                .insert(position, Node::Element(string_field(key, value, protected)));
        }
    }
}

fn set_time(entry: &mut Element, name: &str, time: &str) {
    set_child_text(child_or_append(entry, "Times"), name, time);
}

/// KeePassXC writes `PreviousParentGroup` right after `Times` and
/// `QualityCheck`.
fn set_previous_parent_group(entry: &mut Element, group: &[u8; UUID_LENGTH]) {
    let encoded = encode_uuid(group);
    match entry.child_mut("PreviousParentGroup") {
        Some(existing) => replace_text(existing, &encoded),
        None => {
            let position = entry
                .children
                .iter()
                .rposition(|child| is_element(child, "Times") || is_element(child, "QualityCheck"))
                .map_or(0, |index| index + 1);
            entry.children.insert(
                position,
                Node::Element(text("PreviousParentGroup", &encoded)),
            );
        }
    }
}

/// Drops the oldest history items beyond `Meta/HistoryMaxItems`, then the
/// oldest ones once the newest items together exceed `Meta/HistoryMaxSize`,
/// as `Entry::truncateHistory` does. KeePassXC sizes an item by its
/// attributes, auto-type, attachments, custom data and tags; this counts
/// every text node and the attachments, about a hundred bytes more per item.
fn truncate_history(entry: &mut Element, limits: &HistoryLimits, attachment_sizes: &[usize]) {
    let Some(history) = entry.child_mut("History") else {
        return;
    };
    let items: Vec<usize> = history
        .children
        .iter()
        .enumerate()
        .filter(|(_, child)| is_element(child, "Entry"))
        .map(|(index, _)| index)
        .collect();
    let mut drop_oldest = limits
        .max_items
        .map_or(0, |max| items.len().saturating_sub(max));
    if let Some(max_size) = limits.max_size {
        let mut size = 0usize;
        for (position, &index) in items.iter().enumerate().skip(drop_oldest).rev() {
            if let Node::Element(item) = &history.children[index] {
                size = size.saturating_add(history_item_size(item, attachment_sizes));
            }
            if size > max_size {
                drop_oldest = position + 1;
                break;
            }
        }
    }
    for &index in items[..drop_oldest].iter().rev() {
        history.children.remove(index);
    }
}

fn history_item_size(item: &Element, attachment_sizes: &[usize]) -> usize {
    let mut size = 0usize;
    let mut pending = vec![item];
    while let Some(element) = pending.pop() {
        for child in &element.children {
            match child {
                Node::Text(text) => size = size.saturating_add(text.len()),
                Node::Element(child) => pending.push(child),
            }
        }
        if element.name == "Binary" {
            let attachment = element
                .child("Value")
                .and_then(|value| value.attribute("Ref"))
                .and_then(|reference| reference.parse::<usize>().ok())
                .and_then(|index| attachment_sizes.get(index));
            size = size.saturating_add(attachment.copied().unwrap_or(0));
        }
    }
    size
}

/// Inserts an entry where KeePassXC lists it: after the group's entries,
/// before its subgroups.
fn insert_entry(group: &mut Element, entry: Element) {
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
    replace_text(&mut leaf, value);
    leaf
}

fn replace_text(leaf: &mut Element, value: &str) {
    leaf.children.clear();
    if !value.is_empty() {
        leaf.children
            .push(Node::Text(Zeroizing::new(value.to_owned())));
    }
}

fn set_child_text(parent: &mut Element, name: &str, value: &str) {
    replace_text(child_or_append(parent, name), value);
}

fn child_or_append<'a>(parent: &'a mut Element, name: &str) -> &'a mut Element {
    if parent.child(name).is_none() {
        parent
            .children
            .push(Node::Element(element(name, Vec::new())));
    }
    parent.child_mut(name).expect("the child was just appended")
}

fn is_element(node: &Node, name: &str) -> bool {
    matches!(node, Node::Element(element) if element.name == name)
}

fn root_mut(document: &mut Element) -> Result<&mut Element> {
    document
        .child_mut("Root")
        .ok_or(KdbxError::InvalidXml("missing root group"))
}

fn root_group_mut(document: &mut Element) -> Result<&mut Element> {
    root_mut(document)?
        .child_mut("Group")
        .ok_or(KdbxError::InvalidXml("missing root group"))
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

/// Child indices from the document down to the entry with `uuid`, outside
/// history. Paths let the tree be read and then edited without holding a
/// borrow across the two steps.
fn entry_path(document: &Element, uuid: &[u8; UUID_LENGTH]) -> Option<Vec<usize>> {
    let root_index = document
        .children
        .iter()
        .position(|child| is_element(child, "Root"))?;
    let Node::Element(root) = &document.children[root_index] else {
        return None;
    };
    let group_index = root
        .children
        .iter()
        .position(|child| is_element(child, "Group"))?;
    let Node::Element(group) = &root.children[group_index] else {
        return None;
    };
    let mut path = vec![root_index, group_index];
    find_entry(group, uuid, &mut path).then_some(path)
}

fn find_entry(group: &Element, uuid: &[u8; UUID_LENGTH], path: &mut Vec<usize>) -> bool {
    for (index, child) in group.children.iter().enumerate() {
        let Node::Element(child) = child else {
            continue;
        };
        path.push(index);
        let found = match child.name.as_str() {
            "Entry" => child.child("UUID").and_then(decode_uuid).as_ref() == Some(uuid),
            "Group" => find_entry(child, uuid, path),
            _ => false,
        };
        if found {
            return true;
        }
        path.pop();
    }
    false
}

fn descend_mut<'a>(element: &'a mut Element, path: &[usize]) -> Option<&'a mut Element> {
    path.iter().try_fold(element, |current, &index| {
        match current.children.get_mut(index) {
            Some(Node::Element(child)) => Some(child),
            _ => None,
        }
    })
}

/// The groups along a path, outermost first.
fn groups_on_path<'a>(document: &'a Element, path: &[usize]) -> Vec<&'a Element> {
    let mut groups = Vec::new();
    let mut current = document;
    for &index in path {
        match current.children.get(index) {
            Some(Node::Element(child)) => {
                if child.name == "Group" {
                    groups.push(child);
                }
                current = child;
            }
            _ => break,
        }
    }
    groups
}

fn remove_at(document: &mut Element, path: &[usize]) -> Option<Element> {
    let (&last, parents) = path.split_last()?;
    let parent = descend_mut(document, parents)?;
    if last >= parent.children.len() {
        return None;
    }
    match parent.children.remove(last) {
        Node::Element(removed) => Some(removed),
        Node::Text(_) => None,
    }
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
    use crate::kdbx::inner_header::ProtectedStream;

    const NOW: i64 = 1_767_261_600;
    const ENTRY: [u8; 16] = [0x10; 16];
    const ROOT: [u8; 16] = [0x01; 16];
    const BIN: [u8; 16] = [0x52; 16];

    fn build(meta: &str, groups: &str) -> Database {
        let xml = format!(
            "<KeePassFile><Meta>{meta}</Meta><Root><Group><UUID>{}</UUID><Name>Root</Name>\
             {groups}</Group><DeletedObjects/></Root></KeePassFile>",
            encode_uuid(&ROOT)
        );
        Database::from_document(
            xml::parse(xml.as_bytes(), &mut ProtectedStream::new(&[0u8; 64])).unwrap(),
        )
    }

    fn entry_xml(password: &str, history: &str) -> String {
        format!(
            "<Entry><UUID>{}</UUID><Times><LastModificationTime>old</LastModificationTime>\
             <LocationChanged>old</LocationChanged></Times>\
             <String><Key>Title</Key><Value>Login</Value></String>\
             <String><Key>Password</Key><Value Protected=\"True\">{}</Value></String>\
             <AutoType><Enabled>True</Enabled></AutoType><History>{history}</History></Entry>",
            encode_uuid(&ENTRY),
            {
                let mut bytes = password.as_bytes().to_vec();
                ProtectedStream::new(&[0u8; 64]).apply(&mut bytes);
                STANDARD.encode(bytes)
            }
        )
    }

    fn entry(database: &Database) -> super::super::Entry<'_> {
        database
            .entries()
            .unwrap()
            .into_iter()
            .map(|listed| listed.entry)
            .find(|entry| entry.uuid() == Some(ENTRY))
            .expect("entry exists")
    }

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

    #[test]
    fn update_keeps_the_previous_state_in_history() {
        let mut database = build("", &entry_xml("old-secret", ""));
        assert_eq!(
            database.update_entry(
                &ENTRY,
                &[("Title", "Login"), ("Password", "old-secret")],
                NOW
            ),
            Ok(false)
        );
        assert_eq!(entry(&database).history().count(), 0);

        assert_eq!(
            database.update_entry(&ENTRY, &[("Password", "new-secret"), ("PIN", "1234")], NOW),
            Ok(true)
        );
        let updated = entry(&database);
        assert_eq!(*updated.field("Password").unwrap().value(), "new-secret");
        assert!(updated.field("Password").unwrap().is_protected());
        assert_eq!(*updated.field("PIN").unwrap().value(), "1234");
        let names: Vec<&str> = updated
            .element()
            .elements()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["UUID", "Times", "String", "String", "String", "AutoType", "History"]
        );
        let times = updated.element().child("Times").unwrap();
        assert_eq!(
            *times.child("LastModificationTime").unwrap().text(),
            kdbx_time(NOW)
        );
        assert_eq!(
            *times.child("LastAccessTime").unwrap().text(),
            kdbx_time(NOW)
        );
        assert_eq!(*times.child("LocationChanged").unwrap().text(), "old");

        let history: Vec<_> = updated.history().collect();
        assert_eq!(history.len(), 1);
        assert_eq!(*history[0].field("Password").unwrap().value(), "old-secret");
        assert!(history[0].field("PIN").is_none());
        assert!(history[0].element().child("History").is_none());
        assert_eq!(
            *history[0]
                .element()
                .child("Times")
                .unwrap()
                .child("LastModificationTime")
                .unwrap()
                .text(),
            "old"
        );
    }

    #[test]
    fn history_is_trimmed_by_count_and_size() {
        let mut database = build("<HistoryMaxItems>2</HistoryMaxItems>", &entry_xml("p0", ""));
        for password in ["p1", "p2", "p3"] {
            database
                .update_entry(&ENTRY, &[("Password", password)], NOW)
                .unwrap();
        }
        let kept: Vec<String> = entry(&database)
            .history()
            .map(|item| item.field("Password").unwrap().value().to_string())
            .collect();
        assert_eq!(kept, ["p1", "p2"]);

        let mut database = build(
            "<HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>100</HistoryMaxSize>",
            &entry_xml("p0", ""),
        );
        for password in ["p1", "p2", "p3"] {
            database
                .update_entry(&ENTRY, &[("Password", password)], NOW)
                .unwrap();
        }
        // An item holds about 70 bytes of text once its times are set, so only
        // the newest fits.
        let kept: Vec<String> = entry(&database)
            .history()
            .map(|item| item.field("Password").unwrap().value().to_string())
            .collect();
        assert_eq!(kept, ["p2"]);
    }

    #[test]
    fn delete_moves_to_a_recycle_bin_created_on_demand_then_removes_for_good() {
        let mut database = build(
            "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==\
             </RecycleBinUUID><RecycleBinChanged>old</RecycleBinChanged>",
            &entry_xml("secret", ""),
        );
        assert_eq!(database.deletes_permanently(&ENTRY), Ok(false));
        assert_eq!(database.delete_entry(&ENTRY, NOW), Ok(false));

        let bin = database.recycle_bin().expect("recycle bin created");
        let root = database.root_group().unwrap();
        assert_eq!(root.entries().count(), 0);
        let bin_group = root.groups().find(|g| g.uuid() == Some(bin)).unwrap();
        assert_eq!(*bin_group.name(), "Recycle Bin");
        assert_eq!(*bin_group.element().child("IconID").unwrap().text(), "43");
        assert_eq!(
            *bin_group.element().child("EnableSearching").unwrap().text(),
            "false"
        );
        let meta = database.meta().unwrap();
        assert_eq!(
            *meta.child("RecycleBinChanged").unwrap().text(),
            kdbx_time(NOW)
        );

        let moved = entry(&database);
        assert_eq!(bin_group.entries().count(), 1);
        assert_eq!(
            *moved
                .element()
                .child("Times")
                .unwrap()
                .child("LocationChanged")
                .unwrap()
                .text(),
            kdbx_time(NOW)
        );
        assert_eq!(
            *moved.element().child("PreviousParentGroup").unwrap().text(),
            encode_uuid(&ROOT)
        );
        let names: Vec<&str> = moved
            .element()
            .elements()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names[..3], ["UUID", "Times", "PreviousParentGroup"]);

        assert_eq!(database.deletes_permanently(&ENTRY), Ok(true));
        assert_eq!(database.delete_entry(&ENTRY, NOW), Ok(true));
        assert!(database.entries().unwrap().is_empty());
        let deleted = database.deleted_objects();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].uuid, ENTRY);
        assert_eq!(deleted[0].deletion_time, kdbx_time(NOW));
        assert_eq!(
            database.delete_entry(&ENTRY, NOW),
            Err(KdbxError::UnknownEntry)
        );
    }

    #[test]
    fn delete_is_permanent_when_the_recycle_bin_is_disabled() {
        let mut database = build(
            &format!(
                "<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>{}</RecycleBinUUID>",
                encode_uuid(&BIN)
            ),
            &format!(
                "{}<Group><UUID>{}</UUID><Name>Recycle Bin</Name></Group>",
                entry_xml("secret", ""),
                encode_uuid(&BIN)
            ),
        );
        assert_eq!(database.deletes_permanently(&ENTRY), Ok(true));
        assert_eq!(database.delete_entry(&ENTRY, NOW), Ok(true));
        assert_eq!(database.deleted_objects().len(), 1);
        assert_eq!(database.root_group().unwrap().groups().count(), 1);
    }
}
