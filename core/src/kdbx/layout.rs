//! Elements as KeePassXC writes them (`KdbxXmlWriter.cpp`) and the field
//! and time setters its `Entry.cpp` and `Group.cpp` use, so files changed on
//! the phone look like files changed in KeePassXC.

use zeroize::Zeroizing;

use super::database::{encode_uuid, UUID_LENGTH};
use super::error::{KdbxError, Result};
use super::time::kdbx_time;
use super::xml::{self, Element, Node};
use crate::random;

pub(super) const STANDARD_KEYS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
// KeePassXC's defaults for Meta/HistoryMaxItems and Meta/HistoryMaxSize.
pub(super) const DEFAULT_HISTORY_MAX_ITEMS: i64 = 10;
pub(super) const DEFAULT_HISTORY_MAX_SIZE: i64 = 6 * 1024 * 1024;
// KeePassXC's Group::DefaultIconNumber and Group::RecycleBinIconNumber.
pub(super) const GROUP_ICON: &str = "48";
pub(super) const RECYCLE_BIN_ICON: &str = "43";
pub(super) const NO_UUID: [u8; UUID_LENGTH] = [0; UUID_LENGTH];
/// The entry CustomData key that records `NewEntry::origin`.
pub(super) const ORIGIN_KEY: &str = "SailVault/ImportedFrom";
pub const ORIGIN_BITWARDEN: &str = "Bitwarden";
pub(super) const KNOWN_ORIGINS: [&str; 1] = [ORIGIN_BITWARDEN];
// Entry children that KeePassXC writes after the String elements.
const AFTER_STRINGS: [&str; 4] = ["Binary", "AutoType", "CustomData", "History"];

/// A field of an entry built in the core. The standard keys are protected
/// as `Meta/MemoryProtection` says; `protected` applies to the others.
pub struct NewField {
    pub key: String,
    pub value: Zeroizing<String>,
    pub protected: bool,
}

impl NewField {
    pub fn new(key: impl Into<String>, value: &str, protected: bool) -> Self {
        Self {
            key: key.into(),
            value: Zeroizing::new(value.to_owned()),
            protected,
        }
    }
}

/// An entry built in the core, such as an imported one. Times are seconds
/// since the Unix epoch; missing times are the time of the change.
#[derive(Default)]
pub struct NewEntry {
    /// The identity used to recognise the entry when it is merged again; a
    /// random UUID when missing.
    pub uuid: Option<[u8; UUID_LENGTH]>,
    /// Where an imported entry came from, kept in its CustomData. A later
    /// merge only updates entries of the same origin, so an import can never
    /// change an entry it did not create, whatever UUID it claims.
    pub origin: Option<&'static str>,
    pub fields: Vec<NewField>,
    pub tags: Vec<String>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    /// Oldest first. History items keep only their fields and times.
    pub history: Vec<NewEntry>,
}

pub(super) fn validate_keys(keys: &[&str]) -> Result<()> {
    for (index, key) in keys.iter().enumerate() {
        if key.is_empty() {
            return Err(KdbxError::InvalidEntry("empty field name"));
        }
        if keys[..index].contains(key) {
            return Err(KdbxError::InvalidEntry("duplicate field"));
        }
    }
    Ok(())
}

/// An entry as KeePassXC's `KdbxXmlWriter::writeEntry` writes it; its
/// history items share its UUID.
pub(super) fn build_entry(
    entry: &NewEntry,
    uuid: &[u8; UUID_LENGTH],
    protected_keys: &[&str],
    now: i64,
) -> Result<Element> {
    let mut element = entry_element(uuid, entry, protected_keys, now)?;
    let history = history_elements(entry, uuid, protected_keys, now)?;
    if let Some(history_element) = element.child_mut("History") {
        history_element
            .children
            .extend(history.into_iter().map(Node::Element));
    }
    Ok(element)
}

pub(super) fn history_elements(
    entry: &NewEntry,
    uuid: &[u8; UUID_LENGTH],
    protected_keys: &[&str],
    now: i64,
) -> Result<Vec<Element>> {
    entry
        .history
        .iter()
        .map(|item| {
            let mut element = entry_element(uuid, item, protected_keys, now)?;
            element
                .children
                .retain(|child| !is_element(child, "History"));
            Ok(element)
        })
        .collect()
}

pub(super) fn entry_element(
    uuid: &[u8; UUID_LENGTH],
    entry: &NewEntry,
    protected_keys: &[&str],
    now: i64,
) -> Result<Element> {
    validate_keys(
        &entry
            .fields
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>(),
    )?;
    let now_time = kdbx_time(now);
    // A time in the future would win every later merge, here and in
    // KeePassXC; it counts as now.
    let created = kdbx_time(entry.created.map_or(now, |time| time.min(now)));
    let modified = kdbx_time(entry.modified.map_or(now, |time| time.min(now)));
    let mut tags: Vec<&str> = entry.tags.iter().map(String::as_str).collect();
    tags.sort_unstable();
    tags.dedup();
    let mut children = vec![
        text("UUID", &encode_uuid(uuid)),
        text("IconID", "0"),
        text("ForegroundColor", ""),
        text("BackgroundColor", ""),
        text("OverrideURL", ""),
        text("Tags", &tags.join(",")),
        times(&modified, &created, &now_time),
    ];
    let field = |key: &str| entry.fields.iter().find(|field| field.key == key);
    for key in STANDARD_KEYS {
        let value = field(key).map_or("", |field| field.value.as_str());
        children.push(string_field(key, value, protected_keys.contains(&key)));
    }
    for field in entry
        .fields
        .iter()
        .filter(|field| !STANDARD_KEYS.contains(&field.key.as_str()))
    {
        children.push(string_field(&field.key, &field.value, field.protected));
    }
    children.push(element(
        "AutoType",
        vec![
            text("Enabled", "True"),
            text("DataTransferObfuscation", "0"),
            text("DefaultSequence", ""),
        ],
    ));
    if let Some(origin) = entry.origin {
        children.push(element(
            "CustomData",
            vec![element(
                "Item",
                vec![text("Key", ORIGIN_KEY), text("Value", origin)],
            )],
        ));
    }
    children.push(element("History", Vec::new()));
    Ok(element("Entry", children))
}

/// A group as KeePassXC's `KdbxXmlWriter::writeGroup` writes it;
/// `enabled` is the tri-state for auto-type and searching.
pub(super) fn build_group(
    uuid: &[u8; UUID_LENGTH],
    name: &str,
    icon: &str,
    enabled: &str,
    time: &str,
) -> Element {
    element(
        "Group",
        vec![
            text("UUID", &encode_uuid(uuid)),
            text("Name", name),
            text("Notes", ""),
            text("IconID", icon),
            times(time, time, time),
            text("IsExpanded", "True"),
            text("DefaultAutoTypeSequence", ""),
            text("EnableAutoType", enabled),
            text("EnableSearching", enabled),
            text("LastTopVisibleEntry", &encode_uuid(&NO_UUID)),
        ],
    )
}

/// Access counts as modification, as in KeePassXC's importers.
pub(super) fn times(modified: &str, created: &str, now: &str) -> Element {
    element(
        "Times",
        vec![
            text("LastModificationTime", modified),
            text("CreationTime", created),
            text("LastAccessTime", modified),
            text("ExpiryTime", now),
            text("Expires", "False"),
            text("UsageCount", "0"),
            text("LocationChanged", now),
        ],
    )
}

fn string_field(key: &str, value: &str, protected: bool) -> Element {
    let mut value_element = element("Value", Vec::new());
    if protected {
        value_element
            .attributes
            .push(("Protected".to_owned(), "True".to_owned()));
    }
    replace_text(&mut value_element, value);
    element("String", vec![text("Key", key), value_element])
}

pub(super) fn deleted_object(uuid: &[u8; UUID_LENGTH], time: &str) -> Element {
    element(
        "DeletedObject",
        vec![text("UUID", &encode_uuid(uuid)), text("DeletionTime", time)],
    )
}

/// The current value of a field: the last `String` with that key, as
/// `Entry::fields` resolves repeats.
pub(super) fn field_value(entry: &Element, key: &str) -> Option<Zeroizing<String>> {
    entry
        .children_named("String")
        .filter(|string| string.child("Key").is_some_and(|k| *k.text() == *key))
        .last()
        .and_then(|string| string.child("Value"))
        .map(Element::text)
}

/// Replaces the value of an existing field, keeping its `Protected`
/// attribute, or appends a new `String` where KeePassXC writes them.
pub(super) fn set_field(entry: &mut Element, key: &str, value: &str, protected: bool) {
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

pub(super) fn set_time(item: &mut Element, name: &str, time: &str) {
    set_child_text(child_or_append(item, "Times"), name, time);
}

/// KeePassXC writes an entry's `PreviousParentGroup` right after `Times`
/// and `QualityCheck`.
pub(super) fn set_entry_previous_parent(entry: &mut Element, group: &[u8; UUID_LENGTH]) {
    let position = entry
        .children
        .iter()
        .rposition(|child| is_element(child, "Times") || is_element(child, "QualityCheck"))
        .map_or(0, |index| index + 1);
    set_previous_parent(entry, group, position);
}

/// KeePassXC writes a group's `PreviousParentGroup` after its own fields,
/// before its entries and subgroups.
pub(super) fn set_group_previous_parent(group: &mut Element, parent: &[u8; UUID_LENGTH]) {
    let position = group
        .children
        .iter()
        .position(|child| is_element(child, "Entry") || is_element(child, "Group"))
        .unwrap_or(group.children.len());
    set_previous_parent(group, parent, position);
}

fn set_previous_parent(item: &mut Element, group: &[u8; UUID_LENGTH], position: usize) {
    let encoded = encode_uuid(group);
    match item.child_mut("PreviousParentGroup") {
        Some(existing) => replace_text(existing, &encoded),
        None => item.children.insert(
            position,
            Node::Element(text("PreviousParentGroup", &encoded)),
        ),
    }
}

/// Inserts an entry where KeePassXC lists it: after the group's entries,
/// before its subgroups.
pub(super) fn insert_entry(group: &mut Element, entry: Element) {
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

pub(super) fn element(name: &str, children: Vec<Element>) -> Element {
    Element {
        name: name.to_owned(),
        attributes: Vec::new(),
        children: children.into_iter().map(Node::Element).collect(),
    }
}

/// A leaf element; an empty value gives an empty element, as KeePassXC
/// writes it.
pub(super) fn text(name: &str, value: &str) -> Element {
    let mut leaf = element(name, Vec::new());
    replace_text(&mut leaf, value);
    leaf
}

/// Unprotected text is stored as the writer represents it, so a save reads
/// back as the same document; protected values are encrypted and kept as
/// they are.
fn replace_text(leaf: &mut Element, value: &str) {
    leaf.children.clear();
    let mut text = Zeroizing::new(String::with_capacity(value.len()));
    if leaf.is_protected() {
        text.push_str(value);
    } else {
        text.extend(value.chars().filter(|&c| xml::is_xml10_char(c)));
    }
    if !text.is_empty() {
        leaf.children.push(Node::Text(text));
    }
}

pub(super) fn set_child_text(parent: &mut Element, name: &str, value: &str) {
    replace_text(child_or_append(parent, name), value);
}

pub(super) fn child_or_append<'a>(parent: &'a mut Element, name: &str) -> &'a mut Element {
    if parent.child(name).is_none() {
        parent
            .children
            .push(Node::Element(element(name, Vec::new())));
    }
    parent.child_mut(name).expect("the child was just appended")
}

pub(super) fn is_element(node: &Node, name: &str) -> bool {
    matches!(node, Node::Element(element) if element.name == name)
}

/// A random (version 4) UUID, as KeePassXC's `QUuid::createUuid` makes them.
pub(super) fn new_uuid() -> Result<[u8; UUID_LENGTH]> {
    let mut uuid = random::array::<UUID_LENGTH>()?;
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(uuid)
}
