//! Merging another copy of the database, as KeePassXC's `Merger` does in
//! its default mode (`KeepNewer`, `src/core/Merger.cpp`), with deletions
//! applied as in its `Synchronize` mode:
//!
//! - Entries and groups match by UUID wherever they are. One only in the
//!   other copy is added with its history.
//! - An entry whose other version has a newer `LastModificationTime` (in
//!   seconds) is replaced by it; the older version goes to the history, and
//!   the histories of both are combined. On a tie this copy wins.
//! - An item moves to the other copy's group when its `LocationChanged` is
//!   newer there. A group takes the other copy's name, notes, icon and
//!   expiry time when its `LastModificationTime` is newer there.
//! - An entry or group recorded in `DeletedObjects` of either copy is
//!   removed unless it changed after the deletion, so emptying the recycle
//!   bin on one device sticks. KeePassXC's default mode keeps such items.
//! - Missing custom icons and database CustomData keys are added; other
//!   database settings stay as they are here.
//!
//! Unlike KeePassXC, the combined history is always kept and trimmed to this
//! database's limits.

use std::collections::{HashMap, HashSet};

use super::database::{decode_uuid, Database, UUID_LENGTH};
use super::edit::{require_group_depth, truncate_history, HistoryLimits};
use super::error::{KdbxError, Result};
use super::inner_header::Binary;
use super::layout::{
    child_or_append, history_item, insert_entry, is_element, set_entry_previous_parent,
    set_group_previous_parent, time_text,
};
use super::time::parse_kdbx_time;
use super::tree::{
    descend, descend_mut, entry_path, group_height, group_path, parent_uuid, remove_at,
    root_group_path, ROOT_GROUP_PATH_LENGTH,
};
use super::xml::{Element, Node};

type Uuid = [u8; UUID_LENGTH];

/// What `Database::merge_from` changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeChanges {
    pub added: usize,
    pub modified: usize,
    pub moved: usize,
    pub deleted: usize,
    pub metadata: bool,
}

impl MergeChanges {
    pub fn any(&self) -> bool {
        *self != Self::default()
    }
}

impl Database {
    /// Merges `other`, another copy of this database such as the one on the
    /// computer, into this one. Nothing changes when an error occurs.
    pub fn merge_from(&mut self, other: &Database) -> Result<MergeChanges> {
        let mut merge = Merge {
            document: self.document().clone(),
            binaries: self.binaries().to_vec(),
            source_binaries: other.binaries(),
            binary_map: HashMap::new(),
            limits: self.history_limits(),
            previous_parent: self.header().minor_version >= 1 || other.header().minor_version >= 1,
            changes: MergeChanges::default(),
        };
        merge.groups(other.document())?;
        merge.entries(other.document())?;
        merge.deletions(other.document())?;
        merge.metadata(other.document());

        let changes = merge.changes;
        if changes.any() {
            let (document, binaries) = (merge.document, merge.binaries);
            *self.document_mut() = document;
            *self.binaries_mut() = binaries;
            self.raise_minor_version(other.header().minor_version);
            self.drop_unused_binaries();
        }
        Ok(changes)
    }
}

struct Merge<'a> {
    document: Element,
    binaries: Vec<Binary>,
    source_binaries: &'a [Binary],
    // Attachment pool indices of the other copy mapped to this one.
    binary_map: HashMap<usize, usize>,
    limits: HistoryLimits,
    previous_parent: bool,
    changes: MergeChanges,
}

/// A structural change, applied after all entries are compared so the paths
/// found before stay valid. KeePassXC appends every added, moved or replaced
/// entry to its group in the order it walks the other copy.
enum Placement {
    Add {
        group: Uuid,
        entry: Element,
    },
    Place {
        uuid: Uuid,
        group: Uuid,
        replacement: Option<Element>,
        moved: bool,
    },
}

impl Merge<'_> {
    /// Adds and moves groups, parents before children, and takes newer group
    /// properties. The root groups correspond whatever their UUIDs.
    fn groups(&mut self, source: &Element) -> Result<()> {
        let (_, source_root) = root_group_path(source).ok_or(missing_root())?;
        let target_root = root_uuid(&self.document)?;
        let mut pending: Vec<(&Element, Uuid)> = child_groups(source_root)
            .map(|group| (group, target_root))
            .collect();
        while let Some((source_group, parent)) = pending.pop() {
            let Some(uuid) = item_uuid(source_group) else {
                continue;
            };
            self.merge_group(source_group, &uuid, &parent)?;
            pending.extend(child_groups(source_group).map(|child| (child, uuid)));
        }
        Ok(())
    }

    fn merge_group(&mut self, source: &Element, uuid: &Uuid, parent: &Uuid) -> Result<()> {
        let parent_path = group_path(&self.document, parent).ok_or(KdbxError::UnknownGroup)?;
        let Some(path) = group_path(&self.document, uuid) else {
            require_group_depth(parent_path.len() + 1)?;
            let group = Element {
                children: source
                    .children
                    .iter()
                    .filter(|child| !is_element(child, "Entry") && !is_element(child, "Group"))
                    .cloned()
                    .collect(),
                ..source.clone()
            };
            descend_mut(&mut self.document, &parent_path)
                .ok_or(KdbxError::UnknownGroup)?
                .children
                .push(Node::Element(group));
            self.changes.added += 1;
            return Ok(());
        };
        if path.len() == ROOT_GROUP_PATH_LENGTH {
            return Ok(());
        }

        let target = descend(&self.document, &path).ok_or(KdbxError::UnknownGroup)?;
        let (target_location, target_modified) = (
            time(target, "LocationChanged"),
            time(target, "LastModificationTime"),
        );
        let in_parent = path.len() == parent_path.len() + 1 && path.starts_with(&parent_path);
        // A move into its own subtree would detach the group from the tree.
        let movable = !in_parent && !parent_path.starts_with(&path);
        if movable && target_location < time(source, "LocationChanged") {
            require_group_depth(parent_path.len() + group_height(target))?;
            let previous_parent = parent_uuid(&self.document, &path[..path.len() - 1]);
            let mut group = remove_at(&mut self.document, &path).ok_or(KdbxError::UnknownGroup)?;
            copy_time(&mut group, source, "LocationChanged");
            if let (true, Some(previous_parent)) = (self.previous_parent, previous_parent) {
                set_group_previous_parent(&mut group, &previous_parent);
            }
            let parent_path = group_path(&self.document, parent).ok_or(KdbxError::UnknownGroup)?;
            descend_mut(&mut self.document, &parent_path)
                .ok_or(KdbxError::UnknownGroup)?
                .children
                .push(Node::Element(group));
            self.changes.moved += 1;
        }

        if target_modified < time(source, "LastModificationTime") {
            let path = group_path(&self.document, uuid).ok_or(KdbxError::UnknownGroup)?;
            let group = descend_mut(&mut self.document, &path).ok_or(KdbxError::UnknownGroup)?;
            for name in ["Name", "Notes", "IconID", "CustomIconUUID"] {
                copy_child(group, source, name);
            }
            copy_time(group, source, "ExpiryTime");
            copy_time(group, source, "LastModificationTime");
            self.changes.modified += 1;
        }
        Ok(())
    }

    /// Compares every entry of the other copy with this one's, then applies
    /// the structural changes.
    fn entries(&mut self, source: &Element) -> Result<()> {
        let (_, source_root) = root_group_path(source).ok_or(missing_root())?;
        let target_root = root_uuid(&self.document)?;
        let mut index = HashMap::new();
        if let Some((mut path, root)) = root_group_path(&self.document) {
            index_entries(root, &mut path, &mut index);
        }

        // An entry deleted here and not changed since is not added back.
        let deleted_at = deletion_times(&self.document, source);
        let mut placements = Vec::new();
        let mut seen = HashSet::new();
        let mut pending = vec![(source_root, target_root)];
        while let Some((source_group, group)) = pending.pop() {
            for entry in source_group.children_named("Entry") {
                let Some(uuid) = item_uuid(entry) else {
                    continue;
                };
                if !seen.insert(uuid) {
                    continue;
                }
                match index.get(&uuid) {
                    None if deleted_at
                        .get(&uuid)
                        .is_some_and(|&deleted| time(entry, "LastModificationTime") <= deleted) => {
                    }
                    None => {
                        let entry = self.adopt(entry);
                        placements.push(Placement::Add { group, entry });
                    }
                    Some(path) => {
                        if let Some(placement) = self.merge_entry(entry, &uuid, path, &group)? {
                            placements.push(placement);
                        }
                    }
                }
            }
            pending.extend(
                child_groups(source_group).filter_map(|child| Some((child, item_uuid(child)?))),
            );
        }
        for placement in placements {
            self.place(placement)?;
        }
        Ok(())
    }

    fn merge_entry(
        &mut self,
        source: &Element,
        uuid: &Uuid,
        path: &[usize],
        group: &Uuid,
    ) -> Result<Option<Placement>> {
        let target = descend(&self.document, path).ok_or(KdbxError::UnknownEntry)?;
        let current_group = parent_uuid(&self.document, path).ok_or(KdbxError::UnknownGroup)?;
        let moved = current_group != *group
            && time(target, "LocationChanged") < time(source, "LocationChanged");
        let destination = if moved { *group } else { current_group };
        let (source_modified, target_modified) = (
            time(source, "LastModificationTime"),
            time(target, "LastModificationTime"),
        );
        let target_history = history_items(target);

        if source_modified > target_modified {
            let replaced = history_item(target);
            let mut replacement = self.adopt(source);
            let source_history = take_history(&mut replacement);
            let history = combine_history(target_history, source_history, Some(replaced), true);
            set_history(&mut replacement, history);
            truncate_history(&mut replacement, &self.limits, &self.binary_sizes());
            self.changes.modified += 1;
            self.changes.moved += usize::from(moved);
            return Ok(Some(Placement::Place {
                uuid: *uuid,
                group: destination,
                replacement: Some(replacement),
                moved,
            }));
        }

        let losing = (target_modified > source_modified).then(|| history_item(source));
        let source_history: Vec<Element> = history_items(source)
            .into_iter()
            .chain(losing)
            .map(|item| self.adopt(&item))
            .collect();
        let history = combine_history(target_history.clone(), source_history, None, false);
        if history != target_history {
            let sizes = self.binary_sizes();
            let target = descend_mut(&mut self.document, path).ok_or(KdbxError::UnknownEntry)?;
            set_history(target, history);
            truncate_history(target, &self.limits, &sizes);
            self.changes.modified += 1;
        }
        if moved {
            self.changes.moved += 1;
            return Ok(Some(Placement::Place {
                uuid: *uuid,
                group: destination,
                replacement: None,
                moved,
            }));
        }
        Ok(None)
    }

    fn place(&mut self, placement: Placement) -> Result<()> {
        match placement {
            Placement::Add { group, entry } => {
                let path = group_path(&self.document, &group).ok_or(KdbxError::UnknownGroup)?;
                insert_entry(
                    descend_mut(&mut self.document, &path).ok_or(KdbxError::UnknownGroup)?,
                    entry,
                );
                self.changes.added += 1;
            }
            Placement::Place {
                uuid,
                group,
                replacement,
                moved,
            } => {
                let path = entry_path(&self.document, &uuid).ok_or(KdbxError::UnknownEntry)?;
                let previous_group = parent_uuid(&self.document, &path);
                let current =
                    remove_at(&mut self.document, &path).ok_or(KdbxError::UnknownEntry)?;
                let mut entry = replacement.unwrap_or(current);
                if let (true, true, Some(previous_group)) =
                    (moved, self.previous_parent, previous_group)
                {
                    set_entry_previous_parent(&mut entry, &previous_group);
                }
                let path = group_path(&self.document, &group).ok_or(KdbxError::UnknownGroup)?;
                insert_entry(
                    descend_mut(&mut self.document, &path).ok_or(KdbxError::UnknownGroup)?,
                    entry,
                );
            }
        }
        Ok(())
    }

    /// Combines the deletions of both copies, keeping the earliest time per
    /// item, and removes what did not change after its deletion. Items that
    /// stay lose their record, as in KeePassXC's `mergeDeletions`.
    fn deletions(&mut self, source: &Element) -> Result<()> {
        let mut records: Vec<(Uuid, Element)> = Vec::new();
        for record in deleted_objects(&self.document)
            .into_iter()
            .chain(deleted_objects(source))
        {
            let Some(uuid) = record.child("UUID").and_then(decode_uuid) else {
                continue;
            };
            match records.iter_mut().find(|(known, _)| *known == uuid) {
                Some((_, known))
                    if time_of(record, "DeletionTime") < time_of(known, "DeletionTime") =>
                {
                    *known = record.clone();
                }
                Some(_) => {}
                None => records.push((uuid, record.clone())),
            }
        }
        if records.is_empty() {
            return Ok(());
        }

        let deleted_at: HashMap<Uuid, Option<i64>> = records
            .iter()
            .map(|(uuid, record)| (*uuid, time_of(record, "DeletionTime")))
            .collect();
        let mut kept = HashSet::new();
        let mut entries = Vec::new();
        if let Some((mut path, root)) = root_group_path(&self.document) {
            let mut index = HashMap::new();
            index_entries(root, &mut path, &mut index);
            for (uuid, path) in index {
                let Some(&deleted) = deleted_at.get(&uuid) else {
                    continue;
                };
                let entry = descend(&self.document, &path).ok_or(KdbxError::UnknownEntry)?;
                if time(entry, "LastModificationTime") > deleted {
                    kept.insert(uuid);
                } else {
                    entries.push(path);
                }
            }
        }
        entries.sort_unstable_by(|a, b| b.cmp(a));
        for path in &entries {
            remove_at(&mut self.document, path);
        }
        self.changes.deleted += entries.len();

        let mut groups: Vec<(Vec<usize>, Uuid)> = deleted_at
            .keys()
            .filter_map(|uuid| Some((group_path(&self.document, uuid)?, *uuid)))
            .filter(|(path, _)| path.len() > ROOT_GROUP_PATH_LENGTH)
            .collect();
        // Children before parents: a parent path sorts before its children.
        groups.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (path, uuid) in groups {
            let group = descend(&self.document, &path).ok_or(KdbxError::UnknownGroup)?;
            let empty = !group
                .elements()
                .any(|child| child.name == "Entry" || child.name == "Group");
            if empty && time(group, "LastModificationTime") <= deleted_at[&uuid] {
                remove_at(&mut self.document, &path);
                self.changes.deleted += 1;
            } else {
                kept.insert(uuid);
            }
        }

        let combined: Vec<Node> = records
            .into_iter()
            .filter(|(uuid, _)| !kept.contains(uuid))
            .map(|(_, record)| Node::Element(record))
            .collect();
        let root = self.document.child_mut("Root").ok_or(missing_root())?;
        let deleted = child_or_append(root, "DeletedObjects");
        let before: Vec<&Element> = deleted.children_named("DeletedObject").collect();
        let after: Vec<&Element> = combined
            .iter()
            .filter_map(|node| match node {
                Node::Element(element) => Some(element),
                Node::Text(_) => None,
            })
            .collect();
        if before != after {
            deleted.children = combined;
            self.changes.metadata = true;
        }
        Ok(())
    }

    /// Adds custom icons and database CustomData items this copy lacks.
    fn metadata(&mut self, source: &Element) {
        let Some(source_meta) = source.child("Meta") else {
            return;
        };
        let Some(meta) = self.document.child_mut("Meta") else {
            return;
        };
        for (list, item, key) in [
            ("CustomIcons", "Icon", "UUID"),
            ("CustomData", "Item", "Key"),
        ] {
            let Some(source_list) = source_meta.child(list) else {
                continue;
            };
            let key_of = |element: &Element| element.child(key).map(Element::text);
            let missing: Vec<Node> = source_list
                .children_named(item)
                .filter(|source_item| {
                    let name = key_of(source_item);
                    name.is_some()
                        && !meta.child(list).is_some_and(|known| {
                            known
                                .children_named(item)
                                .any(|existing| key_of(existing) == name)
                        })
                })
                .map(|source_item| Node::Element(source_item.clone()))
                .collect();
            if !missing.is_empty() {
                child_or_append(meta, list).children.extend(missing);
                self.changes.metadata = true;
            }
        }
    }

    /// A copy of an element from the other database with its attachment
    /// references pointing into this database's pool, where equal content
    /// is shared.
    fn adopt(&mut self, element: &Element) -> Element {
        let mut copy = element.clone();
        self.remap_attachments(&mut copy);
        copy
    }

    fn remap_attachments(&mut self, element: &mut Element) {
        if element.name == "Binary" {
            if let Some((_, reference)) = element
                .child_mut("Value")
                .and_then(|value| value.attributes.iter_mut().find(|(key, _)| key == "Ref"))
            {
                if let Some(index) = reference.parse().ok().and_then(|i| self.target_binary(i)) {
                    *reference = index.to_string();
                }
            }
            return;
        }
        for child in &mut element.children {
            if let Node::Element(child) = child {
                self.remap_attachments(child);
            }
        }
    }

    fn target_binary(&mut self, source_index: usize) -> Option<usize> {
        if let Some(&index) = self.binary_map.get(&source_index) {
            return Some(index);
        }
        let binary = self.source_binaries.get(source_index)?;
        let index = match self
            .binaries
            .iter()
            .position(|existing| existing.data == binary.data)
        {
            Some(index) => index,
            None => {
                self.binaries.push(binary.clone());
                self.binaries.len() - 1
            }
        };
        self.binary_map.insert(source_index, index);
        Some(index)
    }

    fn binary_sizes(&self) -> Vec<usize> {
        self.binaries
            .iter()
            .map(|binary| binary.data.len())
            .collect()
    }
}

/// Combines two histories by modification second, as KeePass does: an item
/// of the other copy fills a second this copy has no item for or, when the
/// other version won, replaces this copy's items of that second. `losing`,
/// this copy's replaced version, only fills a free second. This copy's
/// items stay as they are, also several in one second, so merging an
/// unchanged copy changes nothing.
fn combine_history(
    target: Vec<Element>,
    source: Vec<Element>,
    losing: Option<Element>,
    source_wins: bool,
) -> Vec<Element> {
    let mut items: Vec<(Option<i64>, Element)> = target
        .into_iter()
        .map(|item| (time(&item, "LastModificationTime"), item))
        .collect();
    for item in source {
        let second = time(&item, "LastModificationTime");
        let taken = items.iter().any(|(known, _)| *known == second);
        if taken && source_wins {
            items.retain(|(known, _)| *known != second);
        }
        if !taken || source_wins {
            items.push((second, item));
        }
    }
    if let Some(item) = losing {
        let second = time(&item, "LastModificationTime");
        if items.iter().all(|(known, _)| *known != second) {
            items.push((second, item));
        }
    }
    items.sort_by_key(|(second, _)| *second);
    items.into_iter().map(|(_, item)| item).collect()
}

/// Subgroups in reverse, for a stack that visits them in document order.
fn child_groups(group: &Element) -> impl Iterator<Item = &Element> {
    group
        .children_named("Group")
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
}

fn history_items(entry: &Element) -> Vec<Element> {
    entry
        .child("History")
        .map(|history| history.children_named("Entry").cloned().collect())
        .unwrap_or_default()
}

fn take_history(entry: &mut Element) -> Vec<Element> {
    entry
        .child_mut("History")
        .map(|history| {
            std::mem::take(&mut history.children)
                .into_iter()
                .filter_map(|child| match child {
                    Node::Element(item) if item.name == "Entry" => Some(item),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn set_history(entry: &mut Element, items: Vec<Element>) {
    child_or_append(entry, "History").children = items.into_iter().map(Node::Element).collect();
}

fn index_entries(group: &Element, path: &mut Vec<usize>, index: &mut HashMap<Uuid, Vec<usize>>) {
    for (position, child) in group.children.iter().enumerate() {
        let Node::Element(child) = child else {
            continue;
        };
        path.push(position);
        match child.name.as_str() {
            "Entry" => {
                if let Some(uuid) = item_uuid(child) {
                    index.entry(uuid).or_insert_with(|| path.clone());
                }
            }
            "Group" => index_entries(child, path, index),
            _ => {}
        }
        path.pop();
    }
}

/// The earliest deletion time of each item either copy records.
fn deletion_times(target: &Element, source: &Element) -> HashMap<Uuid, Option<i64>> {
    let mut times: HashMap<Uuid, Option<i64>> = HashMap::new();
    for record in deleted_objects(target)
        .into_iter()
        .chain(deleted_objects(source))
    {
        if let Some(uuid) = record.child("UUID").and_then(decode_uuid) {
            let time = time_of(record, "DeletionTime");
            times
                .entry(uuid)
                .and_modify(|known| *known = (*known).min(time))
                .or_insert(time);
        }
    }
    times
}

fn deleted_objects(document: &Element) -> Vec<&Element> {
    document
        .child("Root")
        .and_then(|root| root.child("DeletedObjects"))
        .map(|deleted| deleted.children_named("DeletedObject").collect())
        .unwrap_or_default()
}

fn item_uuid(item: &Element) -> Option<Uuid> {
    item.child("UUID").and_then(decode_uuid)
}

fn root_uuid(document: &Element) -> Result<Uuid> {
    root_group_path(document)
        .and_then(|(_, root)| item_uuid(root))
        .ok_or(missing_root())
}

fn missing_root() -> KdbxError {
    KdbxError::InvalidXml("missing root group")
}

/// A time under `Times`; an unreadable time sorts before every valid one.
fn time(item: &Element, name: &str) -> Option<i64> {
    time_text(item, name).and_then(|text| parse_kdbx_time(&text))
}

fn time_of(element: &Element, name: &str) -> Option<i64> {
    element
        .child(name)
        .and_then(|time| parse_kdbx_time(&time.text()))
}

fn copy_time(target: &mut Element, source: &Element, name: &str) {
    if let Some(value) = source.child("Times").and_then(|times| times.child(name)) {
        let times = child_or_append(target, "Times");
        match times.child_mut(name) {
            Some(existing) => *existing = value.clone(),
            None => times.children.push(Node::Element(value.clone())),
        }
    }
}

fn copy_child(target: &mut Element, source: &Element, name: &str) {
    match source.child(name) {
        Some(value) => match target.child_mut(name) {
            Some(existing) => *existing = value.clone(),
            None => target.children.push(Node::Element(value.clone())),
        },
        None => target.children.retain(|child| !is_element(child, name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx::database::encode_uuid;
    use crate::kdbx::inner_header::ProtectedStream;
    use crate::kdbx::time::kdbx_time;
    use crate::kdbx::{xml, Group};

    const DAY: i64 = 86_400;
    const ROOT: Uuid = [0xA0; UUID_LENGTH];

    fn uuid(id: u8) -> String {
        encode_uuid(&[id; UUID_LENGTH])
    }

    fn times(modified: i64, location: i64) -> String {
        format!(
            "<Times><LastModificationTime>{}</LastModificationTime>\
             <LocationChanged>{}</LocationChanged></Times>",
            kdbx_time(modified),
            kdbx_time(location)
        )
    }

    fn entry(id: u8, title: &str, modified: i64, location: i64, history: &str) -> String {
        format!(
            "<Entry><UUID>{}</UUID>{}<String><Key>Title</Key><Value>{title}</Value></String>\
             <History>{history}</History></Entry>",
            uuid(id),
            times(modified, location)
        )
    }

    fn item(title: &str, modified: i64) -> String {
        format!(
            "<Entry><UUID>{}</UUID>{}<String><Key>Title</Key><Value>{title}</Value></String></Entry>",
            uuid(1),
            times(modified, 0)
        )
    }

    fn group(id: u8, name: &str, modified: i64, location: i64, content: &str) -> String {
        format!(
            "<Group><UUID>{}</UUID><Name>{name}</Name>{}{content}</Group>",
            uuid(id),
            times(modified, location)
        )
    }

    fn database(groups: &str, deleted: &str) -> Database {
        let xml = format!(
            "<KeePassFile><Meta/><Root><Group><UUID>{}</UUID><Name>Root</Name>{groups}</Group>\
             <DeletedObjects>{deleted}</DeletedObjects></Root></KeePassFile>",
            encode_uuid(&ROOT)
        );
        Database::from_document(
            xml::parse(xml.as_bytes(), &mut ProtectedStream::new(&[0u8; 64])).unwrap(),
        )
    }

    fn deleted(id: u8, time: i64) -> String {
        format!(
            "<DeletedObject><UUID>{}</UUID><DeletionTime>{}</DeletionTime></DeletedObject>",
            uuid(id),
            kdbx_time(time)
        )
    }

    /// "group path: title" for every entry, then every group path.
    fn layout(database: &Database) -> Vec<String> {
        fn walk(group: Group<'_>, parent: &str, out: &mut Vec<String>) {
            let path = format!("{parent}/{}", group.name().as_str());
            out.push(path.clone());
            for entry in group.entries() {
                out.push(format!(
                    "{path}: {}",
                    entry.field("Title").unwrap().value().as_str()
                ));
            }
            for child in group.groups() {
                walk(child, &path, out);
            }
        }
        let mut out = Vec::new();
        walk(database.root_group().unwrap(), "", &mut out);
        out
    }

    fn history(database: &Database, id: u8) -> Vec<String> {
        database
            .entry(&[id; UUID_LENGTH])
            .unwrap()
            .history()
            .map(|item| item.field("Title").unwrap().value().to_string())
            .collect()
    }

    #[test]
    fn a_group_moved_later_elsewhere_moves_here_with_its_content() {
        let mut target = database(
            &(group(2, "A", 0, 0, "") + &group(3, "B", 0, 0, &entry(1, "e", 0, 0, ""))),
            "",
        );
        let source = database(
            &group(
                2,
                "A",
                0,
                0,
                &group(3, "B", 0, DAY, &entry(1, "e", 0, 0, "")),
            ),
            "",
        );
        let changes = target.merge_from(&source).unwrap();
        assert_eq!(changes.moved, 1);
        assert_eq!(
            layout(&target),
            ["/Root", "/Root/A", "/Root/A/B", "/Root/A/B: e"]
        );
        // Moved here later than there: it stays, and gets the new entry.
        let mut target = database(
            &(group(2, "A", 0, 0, "") + &group(3, "B", 0, 2 * DAY, "")),
            "",
        );
        let changes = target.merge_from(&source).unwrap();
        assert_eq!((changes.moved, changes.added), (0, 1));
        assert_eq!(
            layout(&target),
            ["/Root", "/Root/A", "/Root/B", "/Root/B: e"]
        );
    }

    #[test]
    fn a_group_never_moves_into_its_own_subtree() {
        let mut target = database(&group(2, "A", 0, 0, &group(3, "B", 0, 0, "")), "");
        let source = database(&group(3, "B", 0, DAY, &group(2, "A", 0, DAY, "")), "");
        target.merge_from(&source).unwrap();
        let layout = layout(&target);
        assert!(layout.contains(&"/Root/B".to_owned()), "{layout:?}");
        assert!(layout.contains(&"/Root/B/A".to_owned()), "{layout:?}");
    }

    #[test]
    fn histories_combine_by_second_and_keep_this_copys_items() {
        // Two items of this copy share a second; both stay.
        let mut target = database(
            &entry(1, "now", 3 * DAY, 0, &(item("a", DAY) + &item("a2", DAY))),
            "",
        );
        let source = database(&entry(1, "old", 2 * DAY, 0, &item("b", DAY / 2)), "");
        let changes = target.merge_from(&source).unwrap();
        assert_eq!(changes.modified, 1);
        assert_eq!(history(&target, 1), ["b", "a", "a2", "old"]);

        // The other version is newer: it wins, this one goes to the history,
        // and the other copy's item replaces this copy's of the same second.
        let mut target = database(&entry(1, "mine", DAY, 0, &item("x", DAY / 2)), "");
        let source = database(&entry(1, "theirs", 2 * DAY, 0, &item("y", DAY / 2)), "");
        target.merge_from(&source).unwrap();
        let current = target.entry(&[1; UUID_LENGTH]).unwrap();
        assert_eq!(*current.field("Title").unwrap().value(), "theirs");
        assert_eq!(history(&target, 1), ["y", "mine"]);
    }

    #[test]
    fn on_equal_times_this_copy_wins() {
        let mut target = database(&entry(1, "mine", DAY, 0, ""), "");
        let source = database(&entry(1, "theirs", DAY, 0, ""), "");
        assert!(!target.merge_from(&source).unwrap().any());
        assert_eq!(
            *target
                .entry(&[1; UUID_LENGTH])
                .unwrap()
                .field("Title")
                .unwrap()
                .value(),
            "mine"
        );
    }

    #[test]
    fn empty_deleted_groups_go_and_others_stay_without_their_record() {
        let content =
            group(2, "Empty", 0, 0, "") + &group(3, "Full", 0, 0, &entry(1, "e", 0, 0, ""));
        let mut target = database(&content, "");
        let source = database("", &(deleted(2, DAY) + &deleted(3, DAY)));
        let changes = target.merge_from(&source).unwrap();
        assert_eq!(changes.deleted, 1);
        assert_eq!(layout(&target), ["/Root", "/Root/Full", "/Root/Full: e"]);
        let records: Vec<[u8; UUID_LENGTH]> = target
            .deleted_objects()
            .iter()
            .map(|deleted| deleted.uuid)
            .collect();
        assert_eq!(records, [[2; UUID_LENGTH]]);
    }

    #[test]
    fn an_entry_changed_after_its_deletion_survives() {
        let mut target = database(&entry(1, "kept", 2 * DAY, 0, ""), "");
        let source = database("", &deleted(1, DAY));
        assert_eq!(target.merge_from(&source).unwrap().deleted, 0);
        assert!(target.entry(&[1; UUID_LENGTH]).is_some());
        assert!(target.deleted_objects().is_empty());

        let mut target = database(&entry(1, "gone", DAY, 0, ""), "");
        assert_eq!(target.merge_from(&source).unwrap().deleted, 1);
        assert!(target.entry(&[1; UUID_LENGTH]).is_none());
    }

    #[test]
    fn adopted_attachments_share_equal_content() {
        let attachment = |reference: usize| {
            format!(
                "<Entry><UUID>{}</UUID>{}<Binary><Key>f</Key><Value Ref=\"{reference}\"/></Binary></Entry>",
                uuid(reference as u8 + 5),
                times(0, 0)
            )
        };
        let mut target = database(&attachment(0), "");
        target.binaries_mut().push(Binary {
            protected: true,
            data: b"same".to_vec().into(),
        });
        let mut source = database(&(attachment(0) + &attachment(1)), "");
        source.binaries_mut().push(Binary {
            protected: true,
            data: b"same".to_vec().into(),
        });
        source.binaries_mut().push(Binary {
            protected: true,
            data: b"other".to_vec().into(),
        });
        target.merge_from(&source).unwrap();
        let data: Vec<&[u8]> = target
            .binaries()
            .iter()
            .map(|b| b.data.as_slice())
            .collect();
        assert_eq!(data, [&b"same"[..], b"other"]);
        let added = target.entry(&[6; UUID_LENGTH]).unwrap();
        let reference = added.attachments().next().unwrap();
        assert_eq!(
            target.attachment(&reference).unwrap().data.as_slice(),
            b"other"
        );
    }
}
