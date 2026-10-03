//! Merging imported entries as KeePassXC's `Merger` does.

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
use super::tree::{descend, descend_mut, entry_path, group_path, path_in_group, root_group_path};
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
    deleted: Vec<[u8; UUID_LENGTH]>,
    recycle_bin: Option<[u8; UUID_LENGTH]>,
    now: i64,
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
                    if context
                        .recycle_bin
                        .is_some_and(|bin| path_in_group(document, &path, &bin))
                    {
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
                .map(|tags| tags.text())
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
