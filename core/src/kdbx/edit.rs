//! Changes to the document tree. New elements follow the layout KeePassXC
//! writes (`KdbxXmlWriter.cpp`), and edits follow its `Entry.cpp`,
//! `Group.cpp` and `Database.cpp`, so files changed on the phone look like
//! files changed in KeePassXC.

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
pub(super) const DEFAULT_HISTORY_MAX_ITEMS: i64 = 10;
pub(super) const DEFAULT_HISTORY_MAX_SIZE: i64 = 6 * 1024 * 1024;
// KeePassXC's Group::DefaultIconNumber and Group::RecycleBinIconNumber.
pub(super) const GROUP_ICON: &str = "48";
const RECYCLE_BIN_ICON: &str = "43";
pub(super) const NO_UUID: [u8; UUID_LENGTH] = [0; UUID_LENGTH];
/// The entry CustomData key that records `NewEntry::origin`.
const ORIGIN_KEY: &str = "SailVault/ImportedFrom";
pub const ORIGIN_BITWARDEN: &str = "Bitwarden";
const KNOWN_ORIGINS: [&str; 1] = [ORIGIN_BITWARDEN];
// Entry children that KeePassXC writes after the String elements.
const AFTER_STRINGS: [&str; 4] = ["Binary", "AutoType", "CustomData", "History"];
// A path of this length (Root, Group) is the root group itself.
const ROOT_GROUP_PATH_LENGTH: usize = 2;
// The reader accepts 128 levels of XML. A group's entries, their history
// and fields need up to 8 more, and unknown elements may add some.
const MAX_GROUP_PATH_LENGTH: usize = 100;

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

/// A group with its content, merged in one step by
/// `Database::merge_group_tree`.
pub struct NewGroup {
    pub name: Zeroizing<String>,
    pub entries: Vec<NewEntry>,
    pub groups: Vec<NewGroup>,
}

/// What `Database::merge_group_tree` changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeSummary {
    pub added: usize,
    pub updated: usize,
}

struct MergeContext {
    protected_keys: Vec<&'static str>,
    limits: HistoryLimits,
    attachment_sizes: Vec<usize>,
    deleted: Vec<[u8; UUID_LENGTH]>,
    recycle_bin: Option<[u8; UUID_LENGTH]>,
    now: i64,
}

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
        let entry = NewEntry {
            fields: fields
                .iter()
                .map(|(key, value)| NewField::new(*key, value, false))
                .collect(),
            ..NewEntry::default()
        };
        self.require_outside_recycle_bin(group_uuid)?;
        let protected_keys = self.protected_standard_keys();
        let uuid = new_uuid()?;
        let entry = build_entry(&entry, &uuid, &protected_keys, now)?;
        let group = group_mut(self.document_mut(), group_uuid).ok_or(KdbxError::UnknownGroup)?;
        insert_entry(group, entry);
        Ok(uuid)
    }

    /// Merges `group` into the group of the same name in the root group,
    /// created when missing, in one step: on an error nothing changes.
    /// Subgroups are matched by name. Entries are matched by UUID wherever
    /// they are now, so entries moved elsewhere stay there; entries in the
    /// recycle bin or under `DeletedObjects` are left deleted. A matched
    /// entry is merged as KeePassXC's `Merger` does: the newer side wins and
    /// the other becomes a history item. Fields and attachments that only
    /// the database has are kept, and nothing is removed.
    pub fn merge_group_tree(&mut self, group: &NewGroup, now: i64) -> Result<MergeSummary> {
        if group.name.is_empty() {
            return Err(KdbxError::InvalidGroup("empty name"));
        }
        let context = MergeContext {
            protected_keys: self.protected_standard_keys(),
            limits: self.history_limits(),
            attachment_sizes: self
                .binaries()
                .iter()
                .map(|binary| binary.data.len())
                .collect(),
            deleted: self
                .deleted_objects()
                .iter()
                .map(|deleted| deleted.uuid)
                .collect(),
            recycle_bin: self.recycle_bin(),
            now,
        };
        let mut document = self.document().clone();
        let (root_path, _) =
            root_group_path(&document).ok_or(KdbxError::InvalidXml("missing root group"))?;
        let target = subgroup_or_create(&mut document, &root_path, &group.name, &context)?;
        let mut summary = MergeSummary::default();
        merge_into(&mut document, &target, group, &context, &mut summary)?;
        if summary != MergeSummary::default() {
            *self.document_mut() = document;
            self.drop_unused_binaries();
        }
        Ok(summary)
    }

    /// Adds a group named `name` at the end of the group with `parent_uuid`
    /// and returns its UUID. Searching and auto-type are inherited, as in a
    /// group created in KeePassXC.
    pub fn add_group(
        &mut self,
        parent_uuid: &[u8; UUID_LENGTH],
        name: &str,
        now: i64,
    ) -> Result<[u8; UUID_LENGTH]> {
        if name.is_empty() {
            return Err(KdbxError::InvalidGroup("empty name"));
        }
        self.require_outside_recycle_bin(parent_uuid)?;
        let parent_path =
            group_path(self.document(), parent_uuid).ok_or(KdbxError::UnknownGroup)?;
        require_group_depth(parent_path.len() + 1)?;
        let uuid = new_uuid()?;
        let group = build_group(&uuid, name, GROUP_ICON, "null", &kdbx_time(now));
        let parent = group_mut(self.document_mut(), parent_uuid).ok_or(KdbxError::UnknownGroup)?;
        parent.children.push(Node::Element(group));
        Ok(uuid)
    }

    /// Whether the entry or group with `uuid` is the recycle bin or inside
    /// it.
    pub fn in_recycle_bin(&self, uuid: &[u8; UUID_LENGTH]) -> Result<bool> {
        let path = entry_path(self.document(), uuid)
            .or_else(|| group_path(self.document(), uuid))
            .ok_or(KdbxError::UnknownGroup)?;
        Ok(self.recycle_bin().is_some_and(|bin| {
            groups_on_path(self.document(), &path)
                .iter()
                .any(|group| group.child("UUID").and_then(decode_uuid) == Some(bin))
        }))
    }

    /// KeePassXC offers no new entries or groups in the recycle bin.
    fn require_outside_recycle_bin(&self, group_uuid: &[u8; UUID_LENGTH]) -> Result<()> {
        if self.in_recycle_bin(group_uuid)? {
            return Err(KdbxError::InvalidGroup("inside the recycle bin"));
        }
        Ok(())
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
        validate_keys(&fields.iter().map(|(key, _)| *key).collect::<Vec<_>>())?;
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
        self.drop_unused_binaries();
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
            let time = kdbx_time(now);
            self.deleted_objects_mut()?
                .children
                .push(Node::Element(deleted_object(uuid, &time)));
            self.drop_unused_binaries();
            return Ok(true);
        }

        let bin = self.recycle_bin_or_create(now)?;
        self.move_entry_at(&path, &bin, now)?;
        Ok(false)
    }

    /// Moves the entry with `uuid` to the end of the group with
    /// `group_uuid`, as KeePassXC's `Entry::setGroup` does: only the
    /// location time and, in KDBX 4.1, the previous parent change. Returns
    /// whether the entry moved; it stays put when it is already there.
    pub fn move_entry(
        &mut self,
        uuid: &[u8; UUID_LENGTH],
        group_uuid: &[u8; UUID_LENGTH],
        now: i64,
    ) -> Result<bool> {
        let path = entry_path(self.document(), uuid).ok_or(KdbxError::UnknownEntry)?;
        if group_path(self.document(), group_uuid).is_none() {
            return Err(KdbxError::UnknownGroup);
        }
        if parent_uuid(self.document(), &path) == Some(*group_uuid) {
            return Ok(false);
        }
        self.move_entry_at(&path, group_uuid, now)?;
        Ok(true)
    }

    fn move_entry_at(
        &mut self,
        path: &[usize],
        group_uuid: &[u8; UUID_LENGTH],
        now: i64,
    ) -> Result<()> {
        let previous_group = parent_uuid(self.document(), path);
        let minor_version = self.header().minor_version;
        let mut entry = remove_at(self.document_mut(), path).ok_or(KdbxError::UnknownEntry)?;
        set_time(&mut entry, "LocationChanged", &kdbx_time(now));
        if let (true, Some(previous_group)) = (minor_version >= 1, previous_group) {
            set_entry_previous_parent(&mut entry, &previous_group);
        }
        let group = group_mut(self.document_mut(), group_uuid).ok_or(KdbxError::UnknownGroup)?;
        insert_entry(group, entry);
        Ok(())
    }

    /// Moves the group with `uuid` and everything in it to the recycle bin.
    /// A group inside the bin, the bin itself, a group containing the bin, or
    /// any group while the bin is disabled is removed for good, and every
    /// entry and group in it is recorded under `DeletedObjects`, as
    /// KeePassXC's `Group::~Group` does. The root group cannot be deleted.
    /// Returns whether it was removed for good.
    pub fn delete_group(&mut self, uuid: &[u8; UUID_LENGTH], now: i64) -> Result<bool> {
        let path = group_path(self.document(), uuid).ok_or(KdbxError::UnknownGroup)?;
        if path.len() == ROOT_GROUP_PATH_LENGTH {
            return Err(KdbxError::RootGroupProtected);
        }
        let time = kdbx_time(now);
        if self.group_deletes_permanently_at(&path) {
            let group = remove_at(self.document_mut(), &path).ok_or(KdbxError::UnknownGroup)?;
            let bin_removed = self
                .recycle_bin()
                .is_some_and(|bin| bin == *uuid || contains_group(&group, &bin));
            record_deleted(&group, &time, self.deleted_objects_mut()?);
            if bin_removed {
                let meta = self.meta_mut()?;
                set_child_text(meta, "RecycleBinUUID", &encode_uuid(&NO_UUID));
            }
            self.drop_unused_binaries();
            return Ok(true);
        }

        let bin = self.recycle_bin_or_create(now)?;
        self.move_group_at(&path, &bin, now)?;
        Ok(false)
    }

    /// Renames the group with `uuid`; a rename updates the modification
    /// time, as KeePassXC's `Group::setName` does. Returns whether the name
    /// changed.
    pub fn rename_group(&mut self, uuid: &[u8; UUID_LENGTH], name: &str, now: i64) -> Result<bool> {
        if name.is_empty() {
            return Err(KdbxError::InvalidGroup("empty name"));
        }
        let group = group_mut(self.document_mut(), uuid).ok_or(KdbxError::UnknownGroup)?;
        if group
            .child("Name")
            .is_some_and(|current| *current.text() == *name)
        {
            return Ok(false);
        }
        set_child_text(group, "Name", name);
        let time = kdbx_time(now);
        set_time(group, "LastModificationTime", &time);
        set_time(group, "LastAccessTime", &time);
        Ok(true)
    }

    /// Moves the group with `uuid` and everything in it to the end of the
    /// group with `parent_uuid`, as KeePassXC's `Group::setParent` does. The
    /// root group cannot move, and no group can move into itself or below
    /// itself. Returns whether the group moved.
    pub fn move_group(
        &mut self,
        uuid: &[u8; UUID_LENGTH],
        parent_uuid: &[u8; UUID_LENGTH],
        now: i64,
    ) -> Result<bool> {
        let path = group_path(self.document(), uuid).ok_or(KdbxError::UnknownGroup)?;
        if path.len() == ROOT_GROUP_PATH_LENGTH {
            return Err(KdbxError::RootGroupProtected);
        }
        let parent_path =
            group_path(self.document(), parent_uuid).ok_or(KdbxError::UnknownGroup)?;
        if parent_path.starts_with(&path) {
            return Err(KdbxError::InvalidGroup("cannot move into itself"));
        }
        if parent_path.len() + 1 == path.len() && path.starts_with(&parent_path) {
            return Ok(false);
        }
        self.move_group_at(&path, parent_uuid, now)?;
        Ok(true)
    }

    fn move_group_at(
        &mut self,
        path: &[usize],
        parent_uuid: &[u8; UUID_LENGTH],
        now: i64,
    ) -> Result<()> {
        let parent_path =
            group_path(self.document(), parent_uuid).ok_or(KdbxError::UnknownGroup)?;
        let moved = descend(self.document(), path).ok_or(KdbxError::UnknownGroup)?;
        require_group_depth(parent_path.len() + group_height(moved))?;
        let groups = groups_on_path(self.document(), path);
        let previous_parent = groups
            .len()
            .checked_sub(2)
            .and_then(|parent| groups[parent].child("UUID"))
            .and_then(decode_uuid);
        let minor_version = self.header().minor_version;
        let mut group = remove_at(self.document_mut(), path).ok_or(KdbxError::UnknownGroup)?;
        set_time(&mut group, "LocationChanged", &kdbx_time(now));
        if let (true, Some(previous_parent)) = (minor_version >= 1, previous_parent) {
            set_group_previous_parent(&mut group, &previous_parent);
        }
        let parent = group_mut(self.document_mut(), parent_uuid).ok_or(KdbxError::UnknownGroup)?;
        parent.children.push(Node::Element(group));
        Ok(())
    }

    /// Moves an entry or group out of the recycle bin to the group it was
    /// deleted from, or to the root group when that group is unknown (KDBX
    /// 4.0 keeps no previous group) or deleted too. KeePassXC restores only
    /// entries with a known previous group. Returns the target group.
    pub fn restore(&mut self, uuid: &[u8; UUID_LENGTH], now: i64) -> Result<[u8; UUID_LENGTH]> {
        let bin = self.recycle_bin().ok_or(KdbxError::NotInRecycleBin)?;
        if *uuid == bin || !self.in_recycle_bin(uuid)? {
            return Err(KdbxError::NotInRecycleBin);
        }
        let entry = entry_path(self.document(), uuid);
        let path = match &entry {
            Some(path) => path.clone(),
            None => group_path(self.document(), uuid).ok_or(KdbxError::UnknownGroup)?,
        };
        let element = descend(self.document(), &path).ok_or(KdbxError::UnknownGroup)?;
        let previous = element
            .child("PreviousParentGroup")
            .and_then(decode_uuid)
            .filter(|group| {
                group_path(self.document(), group).is_some()
                    && !self.in_recycle_bin(group).unwrap_or(true)
            });
        let target = match previous {
            Some(group) => group,
            None => self
                .root_group()?
                .uuid()
                .ok_or(KdbxError::InvalidXml("root group without UUID"))?,
        };
        match entry {
            Some(path) => self.move_entry_at(&path, &target, now)?,
            None => self.move_group_at(&path, &target, now)?,
        }
        Ok(target)
    }

    /// Removes everything in the recycle bin for good and records it under
    /// `DeletedObjects`, as KeePassXC's `Database::emptyRecycleBin` does:
    /// the entries, then each subgroup with its content. The bin stays.
    /// Returns whether anything was removed.
    pub fn empty_recycle_bin(&mut self, now: i64) -> Result<bool> {
        let Some(bin) = self
            .recycle_bin()
            .filter(|bin| group_path(self.document(), bin).is_some())
        else {
            return Ok(false);
        };
        let bin_group = group_mut(self.document_mut(), &bin).ok_or(KdbxError::UnknownGroup)?;
        let (removed, kept): (Vec<Node>, Vec<Node>) = std::mem::take(&mut bin_group.children)
            .into_iter()
            .partition(|child| is_element(child, "Entry") || is_element(child, "Group"));
        bin_group.children = kept;
        if removed.is_empty() {
            return Ok(false);
        }
        let mut emptied = element("Group", Vec::new());
        emptied.children = removed;
        let time = kdbx_time(now);
        let deleted = self.deleted_objects_mut()?;
        for entry in emptied.children_named("Entry") {
            if let Some(uuid) = entry.child("UUID").and_then(decode_uuid) {
                deleted
                    .children
                    .push(Node::Element(deleted_object(&uuid, &time)));
            }
        }
        for group in emptied.children_named("Group") {
            record_deleted(group, &time, deleted);
        }
        self.drop_unused_binaries();
        Ok(true)
    }

    /// Whether `delete_entry` or `delete_group` would remove the item with
    /// `uuid` for good instead of moving it to the recycle bin.
    pub fn deletes_permanently(&self, uuid: &[u8; UUID_LENGTH]) -> Result<bool> {
        if let Some(path) = entry_path(self.document(), uuid) {
            return Ok(self.deletes_permanently_at(&path));
        }
        let path = group_path(self.document(), uuid).ok_or(KdbxError::UnknownEntry)?;
        if path.len() == ROOT_GROUP_PATH_LENGTH {
            return Err(KdbxError::RootGroupProtected);
        }
        Ok(self.group_deletes_permanently_at(&path))
    }

    fn deletes_permanently_at(&self, path: &[usize]) -> bool {
        match self.recycle_bin() {
            None => !self.recycle_bin_enabled(),
            Some(bin) => groups_on_path(self.document(), path)
                .iter()
                .any(|group| group.child("UUID").and_then(decode_uuid) == Some(bin)),
        }
    }

    /// The path ends at the group itself, so this also covers the recycle
    /// bin and a group that holds the bin, as KeePassXC's
    /// `DatabaseWidget::deleteGroup` does.
    fn group_deletes_permanently_at(&self, path: &[usize]) -> bool {
        self.deletes_permanently_at(path)
            || self.recycle_bin().is_some_and(|bin| {
                groups_on_path(self.document(), path)
                    .last()
                    .is_some_and(|group| contains_group(group, &bin))
            })
    }

    /// The recycle bin, created like KeePassXC's `Database::createRecycleBin`
    /// when the metadata names none or names a group that does not exist.
    fn recycle_bin_or_create(&mut self, now: i64) -> Result<[u8; UUID_LENGTH]> {
        if let Some(bin) = self
            .recycle_bin()
            .filter(|bin| group_path(self.document(), bin).is_some())
        {
            return Ok(bin);
        }
        let uuid = new_uuid()?;
        let time = kdbx_time(now);
        let group = build_group(&uuid, "Recycle Bin", RECYCLE_BIN_ICON, "false", &time);
        root_group_mut(self.document_mut())?
            .children
            .push(Node::Element(group));
        let meta = self.meta_mut()?;
        set_child_text(meta, "RecycleBinUUID", &encode_uuid(&uuid));
        set_child_text(meta, "RecycleBinChanged", &time);
        Ok(uuid)
    }

    fn meta_mut(&mut self) -> Result<&mut Element> {
        self.document_mut()
            .child_mut("Meta")
            .ok_or(KdbxError::InvalidXml("missing Meta"))
    }

    fn deleted_objects_mut(&mut self) -> Result<&mut Element> {
        Ok(child_or_append(
            root_mut(self.document_mut())?,
            "DeletedObjects",
        ))
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

fn validate_keys(keys: &[&str]) -> Result<()> {
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
fn build_entry(
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

fn history_elements(
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

fn entry_element(
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

fn merge_into(
    document: &mut Element,
    target_path: &[usize],
    group: &NewGroup,
    context: &MergeContext,
    summary: &mut MergeSummary,
) -> Result<()> {
    for entry in &group.entries {
        let mut known = entry
            .uuid
            .filter(|uuid| group_path(document, uuid).is_none());
        if let Some(uuid) = known {
            if context.deleted.contains(&uuid) {
                continue;
            }
            if let Some(path) = entry_path(document, &uuid) {
                let same_origin = descend(document, &path).is_some_and(|existing| {
                    entry.origin.is_some() && origin(existing) == entry.origin
                });
                if same_origin {
                    let in_recycle_bin = context.recycle_bin.is_some_and(|bin| {
                        groups_on_path(document, &path)
                            .iter()
                            .any(|group| group.child("UUID").and_then(decode_uuid) == Some(bin))
                    });
                    if in_recycle_bin {
                        continue;
                    }
                    let existing = descend_mut(document, &path).ok_or(KdbxError::UnknownEntry)?;
                    if merge_entry(existing, entry, &uuid, context)? {
                        summary.updated += 1;
                    }
                    continue;
                }
                // The UUID belongs to an entry this origin did not create.
                known = None;
            }
        }
        let uuid = match known {
            Some(uuid) => uuid,
            None => new_uuid()?,
        };
        let element = build_entry(entry, &uuid, &context.protected_keys, context.now)?;
        let target = descend_mut(document, target_path).ok_or(KdbxError::UnknownGroup)?;
        insert_entry(target, element);
        summary.added += 1;
    }
    for child in &group.groups {
        let child_path = subgroup_or_create(document, target_path, &child.name, context)?;
        merge_into(document, &child_path, child, context, summary)?;
    }
    Ok(())
}

/// The path of the subgroup named `name` below `parent_path`, appended as a
/// new group when there is none. The recycle bin never matches.
fn subgroup_or_create(
    document: &mut Element,
    parent_path: &[usize],
    name: &str,
    context: &MergeContext,
) -> Result<Vec<usize>> {
    if name.is_empty() {
        return Err(KdbxError::InvalidGroup("empty name"));
    }
    require_group_depth(parent_path.len() + 1)?;
    let parent = descend_mut(document, parent_path).ok_or(KdbxError::UnknownGroup)?;
    let existing = parent.children.iter().position(|child| match child {
        Node::Element(group) if group.name == "Group" => {
            group.child("Name").is_some_and(|n| *n.text() == *name)
                && group.child("UUID").and_then(decode_uuid) != context.recycle_bin
        }
        _ => false,
    });
    let index = match existing {
        Some(index) => index,
        None => {
            let uuid = new_uuid()?;
            let time = kdbx_time(context.now);
            parent.children.push(Node::Element(build_group(
                &uuid, name, GROUP_ICON, "null", &time,
            )));
            parent.children.len() - 1
        }
    };
    let mut path = parent_path.to_vec();
    path.push(index);
    Ok(path)
}

/// Merges `imported` into `existing` like KeePassXC's
/// `Merger::resolveEntryConflict_MergeHistories`: when the import is newer
/// its fields replace the current ones and the current state becomes a
/// history item; otherwise the import becomes a history item. History items
/// are combined by modification time. Returns whether anything changed.
fn merge_entry(
    existing: &mut Element,
    imported: &NewEntry,
    uuid: &[u8; UUID_LENGTH],
    context: &MergeContext,
) -> Result<bool> {
    let local_time = existing
        .child("Times")
        .and_then(|times| times.child("LastModificationTime"))
        .and_then(|time| parse_kdbx_time(&time.text()));
    let imported_time = imported
        .modified
        .map_or(context.now, |time| time.min(context.now));
    let mut candidates = history_elements(imported, uuid, &context.protected_keys, context.now)?;
    let mut changed = false;
    match local_time {
        Some(local_time) if local_time == imported_time => {}
        Some(local_time) if local_time > imported_time => {
            let mut snapshot = entry_element(uuid, imported, &context.protected_keys, context.now)?;
            snapshot
                .children
                .retain(|child| !is_element(child, "History"));
            candidates.push(snapshot);
        }
        _ => {
            let mut previous = existing.clone();
            previous
                .children
                .retain(|child| !is_element(child, "History"));
            candidates.push(previous);
            for field in &imported.fields {
                let protected = if STANDARD_KEYS.contains(&field.key.as_str()) {
                    context.protected_keys.contains(&field.key.as_str())
                } else {
                    field.protected
                };
                set_field(existing, &field.key, &field.value, protected);
            }
            let current_tags = existing
                .child("Tags")
                .map(|tags| tags.text())
                .unwrap_or_default();
            let mut tags: Vec<&str> = current_tags
                .split([',', ';'])
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .chain(imported.tags.iter().map(String::as_str))
                .collect();
            tags.sort_unstable();
            tags.dedup();
            let tags = tags.join(",");
            set_child_text(existing, "Tags", &tags);
            let time = kdbx_time(imported_time);
            set_time(existing, "LastModificationTime", &time);
            set_time(existing, "LastAccessTime", &time);
            changed = true;
        }
    }
    if add_history_items(existing, candidates) {
        changed = true;
    }
    if changed {
        truncate_history(existing, &context.limits, &context.attachment_sizes);
    }
    Ok(changed)
}

/// Adds the items whose modification time the history lacks and sorts the
/// history by that time, oldest first. Returns whether any were added.
fn add_history_items(entry: &mut Element, items: Vec<Element>) -> bool {
    let modification_time = |item: &Element| {
        item.child("Times")
            .and_then(|times| times.child("LastModificationTime"))
            .map(|time| time.text().to_string())
    };
    let history = child_or_append(entry, "History");
    let mut known: Vec<String> = history
        .children
        .iter()
        .filter_map(|child| match child {
            Node::Element(item) if item.name == "Entry" => modification_time(item),
            _ => None,
        })
        .collect();
    let mut added = false;
    for item in items {
        let Some(time) = modification_time(&item) else {
            continue;
        };
        if known.contains(&time) {
            continue;
        }
        known.push(time);
        history.children.push(Node::Element(item));
        added = true;
    }
    if added {
        history.children.sort_by_key(|child| match child {
            Node::Element(item) => modification_time(item)
                .and_then(|time| parse_kdbx_time(&time))
                .unwrap_or(i64::MIN),
            Node::Text(_) => i64::MIN,
        });
    }
    added
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
fn times(modified: &str, created: &str, now: &str) -> Element {
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

fn deleted_object(uuid: &[u8; UUID_LENGTH], time: &str) -> Element {
    element(
        "DeletedObject",
        vec![text("UUID", &encode_uuid(uuid)), text("DeletionTime", time)],
    )
}

/// Records a removed group as KeePassXC does: its entries, then each
/// subgroup the same way, then the group itself.
fn record_deleted(group: &Element, time: &str, deleted: &mut Element) {
    for entry in group.children_named("Entry") {
        if let Some(uuid) = entry.child("UUID").and_then(decode_uuid) {
            deleted
                .children
                .push(Node::Element(deleted_object(&uuid, time)));
        }
    }
    for child in group.children_named("Group") {
        record_deleted(child, time, deleted);
    }
    if let Some(uuid) = group.child("UUID").and_then(decode_uuid) {
        deleted
            .children
            .push(Node::Element(deleted_object(&uuid, time)));
    }
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

fn set_time(item: &mut Element, name: &str, time: &str) {
    set_child_text(child_or_append(item, "Times"), name, time);
}

/// KeePassXC writes an entry's `PreviousParentGroup` right after `Times`
/// and `QualityCheck`.
fn set_entry_previous_parent(entry: &mut Element, group: &[u8; UUID_LENGTH]) {
    let position = entry
        .children
        .iter()
        .rposition(|child| is_element(child, "Times") || is_element(child, "QualityCheck"))
        .map_or(0, |index| index + 1);
    set_previous_parent(entry, group, position);
}

/// KeePassXC writes a group's `PreviousParentGroup` after its own fields,
/// before its entries and subgroups.
fn set_group_previous_parent(group: &mut Element, parent: &[u8; UUID_LENGTH]) {
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
    let path = group_path(document, uuid)?;
    descend_mut(document, &path)
}

/// Whether `uuid` names a group below `group`.
/// Refuses groups nested so deep that a saved file could not be read back.
fn require_group_depth(path_length: usize) -> Result<()> {
    if path_length > MAX_GROUP_PATH_LENGTH {
        return Err(KdbxError::LimitExceeded("group depth"));
    }
    Ok(())
}

/// Levels of groups in `group`, itself included.
fn group_height(group: &Element) -> usize {
    1 + group
        .children_named("Group")
        .map(group_height)
        .max()
        .unwrap_or(0)
}

fn contains_group(group: &Element, uuid: &[u8; UUID_LENGTH]) -> bool {
    group.children_named("Group").any(|child| {
        child.child("UUID").and_then(decode_uuid).as_ref() == Some(uuid)
            || contains_group(child, uuid)
    })
}

/// The root group with its path (`Root`, then `Group`) in the document.
fn root_group_path(document: &Element) -> Option<(Vec<usize>, &Element)> {
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
    Some((vec![root_index, group_index], group))
}

/// Child indices from the document down to the entry with `uuid`, outside
/// history. Paths let the tree be read and then edited without holding a
/// borrow across the two steps.
fn entry_path(document: &Element, uuid: &[u8; UUID_LENGTH]) -> Option<Vec<usize>> {
    let (mut path, group) = root_group_path(document)?;
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

/// Child indices from the document down to the group with `uuid`, the root
/// group included.
fn group_path(document: &Element, uuid: &[u8; UUID_LENGTH]) -> Option<Vec<usize>> {
    let (mut path, group) = root_group_path(document)?;
    find_group(group, uuid, &mut path).then_some(path)
}

fn find_group(group: &Element, uuid: &[u8; UUID_LENGTH], path: &mut Vec<usize>) -> bool {
    if group.child("UUID").and_then(decode_uuid).as_ref() == Some(uuid) {
        return true;
    }
    for (index, child) in group.children.iter().enumerate() {
        let Node::Element(child) = child else {
            continue;
        };
        if child.name != "Group" {
            continue;
        }
        path.push(index);
        if find_group(child, uuid, path) {
            return true;
        }
        path.pop();
    }
    false
}

fn descend<'a>(element: &'a Element, path: &[usize]) -> Option<&'a Element> {
    path.iter().try_fold(element, |current, &index| {
        match current.children.get(index) {
            Some(Node::Element(child)) => Some(child),
            _ => None,
        }
    })
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

/// The `NewEntry::origin` recorded in an entry's CustomData.
fn origin(entry: &Element) -> Option<&'static str> {
    let value = entry
        .child("CustomData")?
        .children_named("Item")
        .find(|item| {
            item.child("Key")
                .is_some_and(|key| *key.text() == *ORIGIN_KEY)
        })?
        .child("Value")?
        .text();
    KNOWN_ORIGINS
        .iter()
        .copied()
        .find(|known| *known == value.as_str())
}

/// The UUID of the group holding the entry at `path`.
fn parent_uuid(document: &Element, path: &[usize]) -> Option<[u8; UUID_LENGTH]> {
    groups_on_path(document, path)
        .last()
        .and_then(|group| group.child("UUID"))
        .and_then(decode_uuid)
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
pub(super) fn new_uuid() -> Result<[u8; UUID_LENGTH]> {
    let mut uuid = random::array::<UUID_LENGTH>()?;
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(uuid)
}

/// Seconds since the Unix epoch of a KDBX 4 time, or `None` if it is not
/// one.
pub(crate) fn parse_kdbx_time(text: &str) -> Option<i64> {
    let bytes: [u8; 8] = STANDARD.decode(text.trim()).ok()?.try_into().ok()?;
    i64::from_le_bytes(bytes).checked_sub(UNIX_EPOCH_SECONDS)
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
    const BANKING: [u8; 16] = [0x20; 16];
    const CARDS: [u8; 16] = [0x21; 16];
    const CARD: [u8; 16] = [0x22; 16];

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
        let mut encrypted = password.as_bytes().to_vec();
        ProtectedStream::new(&[0u8; 64]).apply(&mut encrypted);
        format!(
            "<Entry><UUID>{}</UUID><Times><LastModificationTime>old</LastModificationTime>\
             <LocationChanged>old</LocationChanged></Times>\
             <String><Key>Title</Key><Value>Login</Value></String>\
             <String><Key>Password</Key><Value Protected=\"True\">{}</Value></String>\
             <AutoType><Enabled>True</Enabled></AutoType><History>{history}</History></Entry>",
            encode_uuid(&ENTRY),
            STANDARD.encode(encrypted)
        )
    }

    /// Banking with a Cards subgroup holding one entry.
    fn banking_xml() -> String {
        format!(
            "<Group><UUID>{}</UUID><Name>Banking</Name><Times><LocationChanged>old\
             </LocationChanged></Times><Group><UUID>{}</UUID><Name>Cards</Name>\
             <Entry><UUID>{}</UUID><String><Key>Title</Key><Value>Card</Value></String>\
             </Entry></Group></Group>",
            encode_uuid(&BANKING),
            encode_uuid(&CARDS),
            encode_uuid(&CARD)
        )
    }

    fn enabled_bin_meta() -> String {
        format!(
            "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>{}</RecycleBinUUID>",
            encode_uuid(&BIN)
        )
    }

    fn bin_xml() -> String {
        format!(
            "<Group><UUID>{}</UUID><Name>Recycle Bin</Name></Group>",
            encode_uuid(&BIN)
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

    fn group_names(group: &super::super::Group<'_>) -> Vec<String> {
        group.groups().map(|g| g.name().to_string()).collect()
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
            validate_keys(&["Title", ""]),
            Err(KdbxError::InvalidEntry("empty field name"))
        );
        assert_eq!(
            validate_keys(&["Title", "URL", "Title"]),
            Err(KdbxError::InvalidEntry("duplicate field"))
        );
        assert_eq!(validate_keys(&["Title", "PIN"]), Ok(()));
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
            &format!("{}{}", entry_xml("secret", ""), bin_xml()),
        );
        assert_eq!(database.deletes_permanently(&ENTRY), Ok(true));
        assert_eq!(database.delete_entry(&ENTRY, NOW), Ok(true));
        assert_eq!(database.deleted_objects().len(), 1);
        assert_eq!(database.root_group().unwrap().groups().count(), 1);
    }

    #[test]
    fn deleting_a_group_moves_it_with_its_content_to_the_recycle_bin() {
        let mut database = build(
            &enabled_bin_meta(),
            &format!("{}{}", banking_xml(), bin_xml()),
        );
        assert_eq!(database.deletes_permanently(&BANKING), Ok(false));
        assert_eq!(database.delete_group(&BANKING, NOW), Ok(false));

        let root = database.root_group().unwrap();
        assert_eq!(group_names(&root), ["Recycle Bin"]);
        let bin = root.groups().next().unwrap();
        assert_eq!(group_names(&bin), ["Banking"]);
        let banking = bin.groups().next().unwrap();
        assert_eq!(group_names(&banking), ["Cards"]);
        assert_eq!(banking.groups().next().unwrap().entries().count(), 1);
        assert_eq!(
            *banking
                .element()
                .child("Times")
                .unwrap()
                .child("LocationChanged")
                .unwrap()
                .text(),
            kdbx_time(NOW)
        );
        let names: Vec<&str> = banking
            .element()
            .elements()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["UUID", "Name", "Times", "PreviousParentGroup", "Group"]
        );
        assert_eq!(
            *banking
                .element()
                .child("PreviousParentGroup")
                .unwrap()
                .text(),
            encode_uuid(&ROOT)
        );
        assert!(database.deleted_objects().is_empty());

        // Inside the bin the next deletion is final and records everything.
        assert_eq!(database.deletes_permanently(&CARDS), Ok(true));
        assert_eq!(database.delete_group(&BANKING, NOW), Ok(true));
        let deleted: Vec<[u8; 16]> = database
            .deleted_objects()
            .iter()
            .map(|object| object.uuid)
            .collect();
        assert_eq!(deleted, [CARD, CARDS, BANKING]);
        assert_eq!(database.entries().unwrap().len(), 0);
    }

    #[test]
    fn deleting_the_recycle_bin_or_its_holder_is_final_and_unsets_it() {
        let mut database = build(
            &enabled_bin_meta(),
            &format!(
                "<Group><UUID>{}</UUID><Name>Holder</Name>{}</Group>",
                encode_uuid(&BANKING),
                bin_xml()
            ),
        );
        assert_eq!(database.deletes_permanently(&BIN), Ok(true));
        assert_eq!(database.deletes_permanently(&BANKING), Ok(true));
        assert_eq!(database.delete_group(&BANKING, NOW), Ok(true));
        assert_eq!(database.recycle_bin(), None);
        assert!(database.recycle_bin_enabled());
        let deleted: Vec<[u8; 16]> = database
            .deleted_objects()
            .iter()
            .map(|object| object.uuid)
            .collect();
        assert_eq!(deleted, [BIN, BANKING]);
        assert_eq!(
            database.delete_group(&ROOT, NOW),
            Err(KdbxError::RootGroupProtected)
        );
        assert_eq!(
            database.deletes_permanently(&ROOT),
            Err(KdbxError::RootGroupProtected)
        );
    }

    #[test]
    fn moving_an_entry_changes_only_its_location() {
        let mut database = build("", &format!("{}{}", entry_xml("secret", ""), banking_xml()));
        assert_eq!(database.move_entry(&ENTRY, &CARDS, NOW), Ok(true));

        let root = database.root_group().unwrap();
        assert_eq!(root.entries().count(), 0);
        let cards = root.groups().next().unwrap().groups().next().unwrap();
        let titles: Vec<String> = cards
            .entries()
            .map(|entry| entry.field("Title").unwrap().value().to_string())
            .collect();
        assert_eq!(titles, ["Card", "Login"]);

        let moved = entry(&database);
        let times = moved.element().child("Times").unwrap();
        assert_eq!(
            *times.child("LocationChanged").unwrap().text(),
            kdbx_time(NOW)
        );
        assert_eq!(*times.child("LastModificationTime").unwrap().text(), "old");
        assert_eq!(moved.history().count(), 0);
        assert_eq!(
            *moved.element().child("PreviousParentGroup").unwrap().text(),
            encode_uuid(&ROOT)
        );
        assert_eq!(*moved.field("Password").unwrap().value(), "secret");
        assert!(database.deleted_objects().is_empty());

        assert_eq!(database.move_entry(&ENTRY, &CARDS, NOW), Ok(false));
        assert_eq!(
            database.move_entry(&ENTRY, &[0x99; 16], NOW),
            Err(KdbxError::UnknownGroup)
        );
        assert_eq!(
            database.move_entry(&[0x99; 16], &ROOT, NOW),
            Err(KdbxError::UnknownEntry)
        );
    }

    #[test]
    fn new_groups_follow_keepassxc_layout_and_stay_out_of_the_recycle_bin() {
        let mut database = build(
            &enabled_bin_meta(),
            &format!("{}{}", banking_xml(), bin_xml()),
        );
        let mail = database.add_group(&ROOT, "Mail", NOW).unwrap();

        let root = database.root_group().unwrap();
        assert_eq!(group_names(&root), ["Banking", "Recycle Bin", "Mail"]);
        let group = root.groups().last().unwrap();
        assert_eq!(group.uuid(), Some(mail));
        let names: Vec<&str> = group
            .element()
            .elements()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "UUID",
                "Name",
                "Notes",
                "IconID",
                "Times",
                "IsExpanded",
                "DefaultAutoTypeSequence",
                "EnableAutoType",
                "EnableSearching",
                "LastTopVisibleEntry"
            ]
        );
        let child = |name: &str| group.element().child(name).unwrap().text().to_string();
        assert_eq!(child("IconID"), "48");
        assert_eq!(child("EnableSearching"), "null");
        assert_eq!(
            *group
                .element()
                .child("Times")
                .unwrap()
                .child("CreationTime")
                .unwrap()
                .text(),
            kdbx_time(NOW)
        );

        database
            .add_entry(&mail, &[("Title", "Inbox")], NOW)
            .unwrap();
        assert_eq!(database.in_recycle_bin(&mail), Ok(false));
        assert_eq!(database.in_recycle_bin(&BIN), Ok(true));
        assert_eq!(
            database.add_group(&BIN, "Kept", NOW),
            Err(KdbxError::InvalidGroup("inside the recycle bin"))
        );
        assert_eq!(
            database.add_entry(&BIN, &[("Title", "x")], NOW),
            Err(KdbxError::InvalidGroup("inside the recycle bin"))
        );
        assert_eq!(
            database.add_group(&ROOT, "", NOW),
            Err(KdbxError::InvalidGroup("empty name"))
        );
        assert_eq!(
            database.add_group(&[0x99; 16], "x", NOW),
            Err(KdbxError::UnknownGroup)
        );

        assert_eq!(database.delete_group(&BANKING, NOW), Ok(false));
        assert_eq!(database.in_recycle_bin(&CARD), Ok(true));
        assert_eq!(
            database.add_group(&CARDS, "x", NOW),
            Err(KdbxError::InvalidGroup("inside the recycle bin"))
        );
    }

    #[test]
    fn renaming_a_group_updates_its_modification_time() {
        let mut database = build("", &banking_xml());
        assert_eq!(database.rename_group(&BANKING, "Finance", NOW), Ok(true));
        assert_eq!(database.rename_group(&BANKING, "Finance", NOW), Ok(false));
        assert_eq!(
            database.rename_group(&BANKING, "", NOW),
            Err(KdbxError::InvalidGroup("empty name"))
        );
        let root = database.root_group().unwrap();
        let group = root.groups().next().unwrap();
        assert_eq!(*group.name(), "Finance");
        let times = group.element().child("Times").unwrap();
        assert_eq!(
            *times.child("LastModificationTime").unwrap().text(),
            kdbx_time(NOW)
        );
        assert_eq!(*times.child("LocationChanged").unwrap().text(), "old");
    }

    #[test]
    fn groups_move_with_their_content_but_never_into_themselves() {
        let mut database = build("", &format!("{}{}", banking_xml(), bin_xml()));
        assert_eq!(
            database.move_group(&BANKING, &CARDS, NOW),
            Err(KdbxError::InvalidGroup("cannot move into itself"))
        );
        assert_eq!(
            database.move_group(&BANKING, &BANKING, NOW),
            Err(KdbxError::InvalidGroup("cannot move into itself"))
        );
        assert_eq!(
            database.move_group(&ROOT, &BANKING, NOW),
            Err(KdbxError::RootGroupProtected)
        );
        assert_eq!(database.move_group(&BANKING, &ROOT, NOW), Ok(false));
        assert_eq!(database.move_group(&CARDS, &ROOT, NOW), Ok(true));

        let root = database.root_group().unwrap();
        assert_eq!(group_names(&root), ["Banking", "Recycle Bin", "Cards"]);
        let cards = root.groups().last().unwrap();
        assert_eq!(cards.entries().count(), 1);
        assert_eq!(
            *cards.element().child("PreviousParentGroup").unwrap().text(),
            encode_uuid(&BANKING)
        );
        assert_eq!(
            *cards
                .element()
                .child("Times")
                .unwrap()
                .child("LocationChanged")
                .unwrap()
                .text(),
            kdbx_time(NOW)
        );
    }

    #[test]
    fn restoring_returns_items_to_their_previous_group_or_the_root() {
        let mut database = build(
            &enabled_bin_meta(),
            &format!("{}{}{}", entry_xml("secret", ""), banking_xml(), bin_xml()),
        );
        assert_eq!(
            database.restore(&ENTRY, NOW),
            Err(KdbxError::NotInRecycleBin)
        );
        assert_eq!(database.delete_entry(&CARD, NOW), Ok(false));
        assert_eq!(database.restore(&CARD, NOW), Ok(CARDS));
        assert!(!database.in_recycle_bin(&CARD).unwrap());

        // The previous group is deleted too: the entry goes to the root.
        assert_eq!(database.delete_entry(&CARD, NOW), Ok(false));
        assert_eq!(database.delete_group(&BANKING, NOW), Ok(false));
        assert_eq!(database.restore(&CARD, NOW), Ok(ROOT));
        assert_eq!(database.restore(&BANKING, NOW), Ok(ROOT));
        assert_eq!(database.restore(&BIN, NOW), Err(KdbxError::NotInRecycleBin));
        let root = database.root_group().unwrap();
        assert_eq!(group_names(&root), ["Recycle Bin", "Banking"]);
        assert_eq!(root.entries().count(), 2);
    }

    #[test]
    fn emptying_the_recycle_bin_records_everything_and_keeps_the_bin() {
        let mut database = build(
            &enabled_bin_meta(),
            &format!("{}{}{}", entry_xml("secret", ""), banking_xml(), bin_xml()),
        );
        assert_eq!(database.empty_recycle_bin(NOW), Ok(false));
        assert_eq!(database.delete_group(&BANKING, NOW), Ok(false));
        assert_eq!(database.delete_entry(&ENTRY, NOW), Ok(false));
        assert_eq!(database.empty_recycle_bin(NOW), Ok(true));

        let root = database.root_group().unwrap();
        let bin = root.groups().next().unwrap();
        assert_eq!(bin.uuid(), Some(BIN));
        assert_eq!(bin.entries().count() + bin.groups().count(), 0);
        let deleted: Vec<[u8; 16]> = database
            .deleted_objects()
            .iter()
            .map(|deleted| deleted.uuid)
            .collect();
        assert_eq!(deleted, [ENTRY, CARD, CARDS, BANKING]);
        assert_eq!(database.recycle_bin(), Some(BIN));
    }
}
