//! Merging imported entries as KeePassXC's `Merger` does.

use std::collections::{HashMap, HashSet};

use zeroize::Zeroizing;

use super::database::{decode_uuid, Database, UUID_LENGTH};
use super::edit::{require_group_depth, truncate_history, HistoryLimits};
use super::error::{KdbxError, Result};
use super::layout::{
    build_entry, build_group, child_or_append, entry_element, history_elements, history_item,
    insert_entry, new_uuid, set_child_text, set_field, set_time, tags_text, time_text, NewEntry,
    GROUP_ICON, KNOWN_ORIGINS, ORIGIN_KEY, STANDARD_KEYS,
};
use super::time::{kdbx_time, parse_kdbx_time};
use super::tree::{descend, descend_mut, path_in_group, root_group_path};
use super::xml::{Element, Node};

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
    deleted: HashSet<[u8; UUID_LENGTH]>,
    recycle_bin: Option<[u8; UUID_LENGTH]>,
    now: i64,
}

/// Where the document's entries are, and which groups it has, collected
/// once so merging does not search the tree for every imported entry. The
/// paths stay valid while merging: matched entries change in place, new
/// groups are appended, and new entries wait in `Additions`.
#[derive(Default)]
struct UuidIndex {
    entries: HashMap<[u8; UUID_LENGTH], Vec<usize>>,
    groups: HashSet<[u8; UUID_LENGTH]>,
}

impl UuidIndex {
    /// In document order, so the first of repeated UUIDs wins, as in
    /// `entry_path`.
    fn collect(&mut self, group: &Element, path: &mut Vec<usize>) {
        if let Some(uuid) = group.child("UUID").and_then(decode_uuid) {
            self.groups.insert(uuid);
        }
        for (position, child) in group.children.iter().enumerate() {
            let Node::Element(child) = child else {
                continue;
            };
            path.push(position);
            match child.name.as_str() {
                "Entry" => {
                    if let Some(uuid) = child.child("UUID").and_then(decode_uuid) {
                        self.entries.entry(uuid).or_insert_with(|| path.clone());
                    }
                }
                "Group" => self.collect(child, path),
                _ => {}
            }
            path.pop();
        }
    }
}

/// New entries with the path of their group, inserted after the merge.
#[derive(Default)]
struct Additions {
    entries: Vec<(Vec<usize>, Element)>,
    by_uuid: HashMap<[u8; UUID_LENGTH], usize>,
}

impl Additions {
    /// Deepest groups first: an insertion shifts the paths below its group,
    /// which by then are done with. The sort is stable, so the entries of a
    /// group keep their order.
    fn insert_into(mut self, document: &mut Element) -> Result<()> {
        self.entries
            .sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
        for (path, entry) in self.entries {
            insert_entry(
                descend_mut(document, &path).ok_or(KdbxError::UnknownGroup)?,
                entry,
            );
        }
        Ok(())
    }
}

impl Database {
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
        let (root_path, root) =
            root_group_path(&document).ok_or(KdbxError::InvalidXml("missing root group"))?;
        let mut index = UuidIndex::default();
        index.collect(root, &mut root_path.clone());
        let target =
            subgroup_or_create(&mut document, &root_path, &group.name, &context, &mut index)?;
        let mut summary = MergeSummary::default();
        let mut additions = Additions::default();
        merge_into(
            &mut document,
            &target,
            group,
            &context,
            &mut index,
            &mut additions,
            &mut summary,
        )?;
        additions.insert_into(&mut document)?;
        if summary != MergeSummary::default() {
            *self.document_mut() = document;
            self.drop_unused_binaries();
        }
        Ok(summary)
    }
}

fn merge_into(
    document: &mut Element,
    target_path: &[usize],
    group: &NewGroup,
    context: &MergeContext,
    index: &mut UuidIndex,
    additions: &mut Additions,
    summary: &mut MergeSummary,
) -> Result<()> {
    for entry in &group.entries {
        let mut claimed = entry.uuid.filter(|uuid| !index.groups.contains(uuid));
        if let Some(uuid) = claimed {
            if context.deleted.contains(&uuid) {
                continue;
            }
            // The same item twice in one export merges into its new entry.
            if let Some(&pending) = additions.by_uuid.get(&uuid) {
                if merge_entry(&mut additions.entries[pending].1, entry, &uuid, context)? {
                    summary.updated += 1;
                }
                continue;
            }
            if let Some(path) = index.entries.get(&uuid) {
                let same_origin = descend(document, path).is_some_and(|existing| {
                    entry.origin.is_some() && origin(existing) == entry.origin
                });
                if same_origin {
                    if context
                        .recycle_bin
                        .is_some_and(|bin| path_in_group(document, path, &bin))
                    {
                        continue;
                    }
                    let existing = descend_mut(document, path).ok_or(KdbxError::UnknownEntry)?;
                    if merge_entry(existing, entry, &uuid, context)? {
                        summary.updated += 1;
                    }
                    continue;
                }
                // The UUID belongs to an entry this origin did not create.
                claimed = None;
            }
        }
        let uuid = match claimed {
            Some(uuid) => uuid,
            None => new_uuid()?,
        };
        let element = build_entry(entry, &uuid, &context.protected_keys, context.now)?;
        additions.by_uuid.insert(uuid, additions.entries.len());
        additions.entries.push((target_path.to_vec(), element));
        summary.added += 1;
    }
    for child in &group.groups {
        let child_path = subgroup_or_create(document, target_path, &child.name, context, index)?;
        merge_into(
            document,
            &child_path,
            child,
            context,
            index,
            additions,
            summary,
        )?;
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
    index: &mut UuidIndex,
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
            index.groups.insert(uuid);
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
    let local_time =
        time_text(existing, "LastModificationTime").and_then(|time| parse_kdbx_time(&time));
    let imported_time = imported
        .modified
        .map_or(context.now, |time| time.min(context.now));
    let mut candidates = history_elements(imported, uuid, &context.protected_keys, context.now)?;
    let mut changed = false;
    match local_time {
        Some(local_time) if local_time == imported_time => {}
        Some(local_time) if local_time > imported_time => {
            let snapshot = entry_element(uuid, imported, &context.protected_keys, context.now)?;
            candidates.push(history_item(&snapshot));
        }
        _ => {
            candidates.push(history_item(existing));
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
                .map(super::xml::Element::text)
                .unwrap_or_default();
            let tags = tags_text(
                current_tags
                    .split([',', ';'])
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .chain(imported.tags.iter().map(String::as_str)),
            );
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
    let modification_time =
        |item: &Element| time_text(item, "LastModificationTime").map(|time| time.to_string());
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

/// The `NewEntry::origin` recorded in an entry's CustomData.
pub(super) fn origin(entry: &Element) -> Option<&'static str> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx::database::encode_uuid;
    use crate::kdbx::inner_header::ProtectedStream;
    use crate::kdbx::layout::NewField;
    use crate::kdbx::{xml, Group, ORIGIN_BITWARDEN};

    const NOW: i64 = 1_767_261_600;
    const ROOT: [u8; UUID_LENGTH] = [0xA0; UUID_LENGTH];
    const BIN: [u8; UUID_LENGTH] = [0x52; UUID_LENGTH];

    fn database(meta: &str, groups: &str, deleted: &str) -> Database {
        let xml = format!(
            "<KeePassFile><Meta>{meta}</Meta><Root><Group><UUID>{}</UUID><Name>Root</Name>\
             {groups}</Group><DeletedObjects>{deleted}</DeletedObjects></Root></KeePassFile>",
            encode_uuid(&ROOT)
        );
        Database::from_document(
            xml::parse(xml.as_bytes(), &mut ProtectedStream::new(&[0u8; 64])).unwrap(),
        )
    }

    fn imported(id: u8, title: &str, modified: i64) -> NewEntry {
        NewEntry {
            uuid: Some([id; UUID_LENGTH]),
            origin: Some(ORIGIN_BITWARDEN),
            fields: vec![NewField::new("Title", title, false)],
            modified: Some(modified),
            ..NewEntry::default()
        }
    }

    fn group(name: &str, entries: Vec<NewEntry>, groups: Vec<NewGroup>) -> NewGroup {
        NewGroup {
            name: Zeroizing::new(name.to_owned()),
            entries,
            groups,
        }
    }

    fn summary(added: usize, updated: usize) -> Result<MergeSummary> {
        Ok(MergeSummary { added, updated })
    }

    fn title(database: &Database, id: u8) -> String {
        let entry = database.entry(&[id; UUID_LENGTH]).unwrap();
        entry.field("Title").unwrap().value().to_string()
    }

    /// "group path: title" for every entry, in document order.
    fn layout(database: &Database) -> Vec<String> {
        fn walk(group: Group<'_>, parent: &str, out: &mut Vec<String>) {
            let path = format!("{parent}/{}", group.name().as_str());
            for entry in group.entries() {
                let title = entry.field("Title").unwrap().value();
                out.push(format!("{path}: {}", title.as_str()));
            }
            for child in group.groups() {
                walk(child, &path, out);
            }
        }
        let mut out = Vec::new();
        walk(database.root_group().unwrap(), "", &mut out);
        out
    }

    #[test]
    fn new_entries_land_in_their_groups_in_import_order() {
        let mut database = database("", "", "");
        let first = group(
            "Import",
            vec![imported(1, "a", NOW), imported(2, "b", NOW)],
            vec![group(
                "A",
                vec![imported(3, "c", NOW)],
                vec![group("B", vec![imported(4, "d", NOW)], Vec::new())],
            )],
        );
        assert_eq!(database.merge_group_tree(&first, NOW), summary(4, 0));
        // Entries added at every level shift the positions of the groups
        // below them.
        let second = group(
            "Import",
            vec![imported(5, "e", NOW)],
            vec![group(
                "A",
                vec![imported(6, "f", NOW)],
                vec![group("B", vec![imported(7, "g", NOW)], Vec::new())],
            )],
        );
        assert_eq!(database.merge_group_tree(&second, NOW), summary(3, 0));
        assert_eq!(
            layout(&database),
            [
                "/Root/Import: a",
                "/Root/Import: b",
                "/Root/Import: e",
                "/Root/Import/A: c",
                "/Root/Import/A: f",
                "/Root/Import/A/B: d",
                "/Root/Import/A/B: g",
            ]
        );
    }

    #[test]
    fn deleted_entries_stay_deleted_and_group_uuids_are_not_taken() {
        let deleted = format!(
            "<DeletedObject><UUID>{}</UUID><DeletionTime>x</DeletionTime></DeletedObject>",
            encode_uuid(&[9; UUID_LENGTH])
        );
        let other = format!(
            "<Group><UUID>{}</UUID><Name>Other</Name></Group>",
            encode_uuid(&[8; UUID_LENGTH])
        );
        let mut database = database("", &other, &deleted);
        let import = group(
            "Import",
            vec![imported(9, "deleted", NOW), imported(8, "group's", NOW)],
            Vec::new(),
        );
        assert_eq!(database.merge_group_tree(&import, NOW), summary(1, 0));
        assert_eq!(layout(&database), ["/Root/Import: group's"]);
        assert!(database.entry(&[8; UUID_LENGTH]).is_none());
        assert!(database.entry(&[9; UUID_LENGTH]).is_none());
    }

    #[test]
    fn equal_times_change_nothing_and_newer_imports_win_with_trimmed_history() {
        let mut database = database("<HistoryMaxItems>2</HistoryMaxItems>", "", "");
        let at =
            |title: &str, time: i64| group("Import", vec![imported(1, title, time)], Vec::new());
        assert_eq!(
            database.merge_group_tree(&at("v1", NOW - 300), NOW),
            summary(1, 0)
        );
        assert_eq!(
            database.merge_group_tree(&at("v1", NOW - 300), NOW),
            summary(0, 0)
        );
        for (version, time) in [("v2", NOW - 200), ("v3", NOW - 100), ("v4", NOW)] {
            assert_eq!(
                database.merge_group_tree(&at(version, time), NOW),
                summary(0, 1)
            );
        }
        assert_eq!(title(&database, 1), "v4");
        let entry = database.entry(&[1; UUID_LENGTH]).unwrap();
        let history: Vec<String> = entry
            .history()
            .map(|item| item.field("Title").unwrap().value().to_string())
            .collect();
        assert_eq!(history, ["v2", "v3"]);
    }

    #[test]
    fn an_error_leaves_the_database_unchanged() {
        let mut database = database("", "", "");
        let before = database.document().clone();
        let mut repeated_key = imported(2, "twice", NOW);
        repeated_key
            .fields
            .push(NewField::new("Title", "again", false));
        let import = group(
            "Import",
            vec![imported(1, "fine", NOW), repeated_key],
            Vec::new(),
        );
        assert_eq!(
            database.merge_group_tree(&import, NOW),
            Err(KdbxError::InvalidEntry("duplicate field"))
        );
        assert!(*database.document() == before);
    }

    #[test]
    fn an_import_named_like_the_recycle_bin_gets_its_own_group() {
        let meta = format!(
            "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>{}</RecycleBinUUID>",
            encode_uuid(&BIN)
        );
        let bin = format!(
            "<Group><UUID>{}</UUID><Name>Recycle Bin</Name></Group>",
            encode_uuid(&BIN)
        );
        let mut database = database(&meta, &bin, "");
        let import = group("Recycle Bin", vec![imported(1, "a", NOW)], Vec::new());
        assert_eq!(database.merge_group_tree(&import, NOW), summary(1, 0));
        assert_eq!(database.group(&BIN).unwrap().entries().count(), 0);
        assert_eq!(database.root_group().unwrap().groups().count(), 2);
    }

    #[test]
    fn the_same_item_twice_in_one_export_becomes_one_entry() {
        let mut database = database("", "", "");
        let import = group(
            "Import",
            vec![imported(1, "older", NOW - 100), imported(1, "newer", NOW)],
            Vec::new(),
        );
        assert_eq!(database.merge_group_tree(&import, NOW), summary(1, 1));
        assert_eq!(layout(&database), ["/Root/Import: newer"]);
    }
}
