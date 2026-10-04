//! Nextcloud sync settings, kept in an entry of the database so the app
//! password has the master password in front of it (`PLAN.md`, "Sync
//! credentials"). The entry is an ordinary one in the root group, marked by
//! an entry CustomData item, so it survives merges, also in KeePassXC.

use zeroize::Zeroizing;

use super::database::{Database, Entry, UUID_LENGTH};
use super::error::{KdbxError, Result};
use super::layout::{element, is_element, text};
use super::tree::{descend_mut, entry_path};
use super::xml::{Element, Node};

const MARKER_KEY: &str = "SailVault/Sync";
const MARKER_VALUE: &str = "Nextcloud";
pub const SYNC_TITLE: &str = "Nextcloud sync (SailVault)";
const PATH_KEY: &str = "SailVault sync path";
const CERTIFICATE_KEY: &str = "SailVault sync certificate";

/// Where and how the database syncs: the Nextcloud server URL, the login
/// name and app password, the file's path in the user's files, and the
/// SHA-256 fingerprint of a self-signed server certificate the user
/// confirmed, or empty.
#[derive(Default)]
pub struct SyncSettings {
    pub server: Zeroizing<String>,
    pub user: Zeroizing<String>,
    pub app_password: Zeroizing<String>,
    pub path: Zeroizing<String>,
    pub certificate: Zeroizing<String>,
}

impl Database {
    /// The sync entry: the first marked entry outside the recycle bin, so
    /// deleting the entry turns sync off.
    pub fn sync_entry(&self) -> Option<[u8; UUID_LENGTH]> {
        let bin = self.existing_recycle_bin();
        let mut pending = vec![self.root_group().ok()?];
        while let Some(group) = pending.pop() {
            if bin.is_some() && group.uuid() == bin {
                continue;
            }
            if let Some(entry) = group.entries().find(is_sync_entry) {
                return entry.uuid();
            }
            pending.extend(group.groups());
        }
        None
    }

    pub fn sync_settings(&self) -> Option<SyncSettings> {
        let entry = self.entry(&self.sync_entry()?)?;
        let value = |key: &str| {
            entry
                .field(key)
                .map(|field| field.value())
                .unwrap_or_default()
        };
        Some(SyncSettings {
            server: value("URL"),
            user: value("UserName"),
            app_password: value("Password"),
            path: value(PATH_KEY),
            certificate: value(CERTIFICATE_KEY),
        })
    }

    /// Stores the settings in the sync entry, created in the root group when
    /// there is none; a change keeps the previous values in the entry's
    /// history like any edit. Returns the entry's UUID.
    pub fn set_sync_settings(
        &mut self,
        settings: &SyncSettings,
        now: i64,
    ) -> Result<[u8; UUID_LENGTH]> {
        if settings.server.is_empty() || settings.user.is_empty() || settings.path.is_empty() {
            return Err(KdbxError::InvalidEntry("incomplete sync settings"));
        }
        let fields = [
            ("Title", SYNC_TITLE),
            ("URL", settings.server.as_str()),
            ("UserName", settings.user.as_str()),
            ("Password", settings.app_password.as_str()),
            (PATH_KEY, settings.path.as_str()),
            (CERTIFICATE_KEY, settings.certificate.as_str()),
        ];
        if let Some(uuid) = self.sync_entry() {
            self.update_entry(&uuid, &fields, now)?;
            return Ok(uuid);
        }
        let root = self.root_group()?.uuid().ok_or(KdbxError::UnknownGroup)?;
        let uuid = self.add_entry(&root, &fields, now)?;
        let path = entry_path(self.document(), &uuid).ok_or(KdbxError::UnknownEntry)?;
        let entry = descend_mut(self.document_mut(), &path).ok_or(KdbxError::UnknownEntry)?;
        mark(entry);
        Ok(uuid)
    }
}

fn is_sync_entry(entry: &Entry<'_>) -> bool {
    entry.element().child("CustomData").is_some_and(|data| {
        data.children_named("Item").any(|item| {
            item.child("Key")
                .is_some_and(|key| *key.text() == *MARKER_KEY)
                && item
                    .child("Value")
                    .is_some_and(|value| *value.text() == *MARKER_VALUE)
        })
    })
}

/// Removes the marker from an entry and its history items, dropping a
/// CustomData element it leaves empty.
pub(super) fn remove_sync_marker(entry: &mut Element) {
    for child in &mut entry.children {
        let Node::Element(child) = child else {
            continue;
        };
        match child.name.as_str() {
            "CustomData" => child.children.retain(|item| match item {
                Node::Element(item) => item
                    .child("Key")
                    .map_or(true, |key| *key.text() != *MARKER_KEY),
                Node::Text(_) => true,
            }),
            "History" => {
                for item in &mut child.children {
                    if let Node::Element(item) = item {
                        remove_sync_marker(item);
                    }
                }
            }
            _ => {}
        }
    }
    entry.children.retain(|child| match child {
        Node::Element(data) if data.name == "CustomData" => data.elements().next().is_some(),
        _ => true,
    });
}

/// Adds the marker where KeePassXC writes entry CustomData: before the
/// history.
fn mark(entry: &mut Element) {
    let item = element(
        "Item",
        vec![text("Key", MARKER_KEY), text("Value", MARKER_VALUE)],
    );
    if let Some(data) = entry.child_mut("CustomData") {
        data.children.push(Node::Element(item));
        return;
    }
    let position = entry
        .children
        .iter()
        .position(|child| is_element(child, "History"))
        .unwrap_or(entry.children.len());
    entry
        .children
        .insert(position, Node::Element(element("CustomData", vec![item])));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx::{CompositeKey, KdfLevel};

    const NOW: i64 = 1_767_261_600;

    fn database() -> Database {
        let key = CompositeKey::new(Some(b"test"), None).unwrap();
        Database::create(key, "Test", KdfLevel::Standard, NOW).unwrap()
    }

    fn settings(password: &str) -> SyncSettings {
        SyncSettings {
            server: Zeroizing::new("https://cloud.example.org".to_owned()),
            user: Zeroizing::new("alice".to_owned()),
            app_password: Zeroizing::new(password.to_owned()),
            path: Zeroizing::new("/Passwords/Test.kdbx".to_owned()),
            certificate: Zeroizing::new(String::new()),
        }
    }

    #[test]
    fn settings_live_in_one_marked_entry_with_a_protected_password() {
        let mut database = database();
        assert!(database.sync_settings().is_none());
        let uuid = database.set_sync_settings(&settings("first"), NOW).unwrap();
        assert_eq!(database.sync_entry(), Some(uuid));
        let entry = database.entry(&uuid).unwrap();
        assert_eq!(*entry.field("Title").unwrap().value(), SYNC_TITLE);
        assert!(entry.field("Password").unwrap().is_protected());

        // A second setup updates the same entry and keeps the old values in
        // its history.
        assert_eq!(
            database
                .set_sync_settings(&settings("second"), NOW + 1)
                .unwrap(),
            uuid
        );
        let stored = database.sync_settings().unwrap();
        assert_eq!(*stored.app_password, "second");
        assert_eq!(*stored.path, "/Passwords/Test.kdbx");
        assert_eq!(database.entry(&uuid).unwrap().history().count(), 1);
    }

    #[test]
    fn a_recycled_sync_entry_turns_sync_off() {
        let mut database = database();
        let uuid = database.set_sync_settings(&settings("x"), NOW).unwrap();
        database.delete_entry(&uuid, NOW + 1).unwrap();
        assert!(database.sync_entry().is_none());
        // Setting up again creates a new entry.
        let again = database.set_sync_settings(&settings("y"), NOW + 2).unwrap();
        assert_ne!(again, uuid);
    }

    fn database_with(password: &[u8]) -> Database {
        let key = CompositeKey::new(Some(password), None).unwrap();
        Database::create(key, "Test", KdfLevel::Standard, NOW).unwrap()
    }

    #[test]
    fn a_merged_foreign_database_cannot_bring_sync_settings() {
        let mut foreign = database_with(b"someone else");
        let uuid = foreign.set_sync_settings(&settings("theirs"), NOW).unwrap();
        foreign
            .update_entry(&uuid, &[("Notes", "edited")], NOW + 1)
            .unwrap();
        let mut mine = database_with(b"mine");
        mine.merge_from(&foreign).unwrap();
        let merged = mine.entry(&uuid).expect("the entry itself is merged");
        assert!(merged.element().child("CustomData").is_none());
        assert!(merged
            .history()
            .all(|item| item.element().child("CustomData").is_none()));
        assert!(mine.sync_entry().is_none());
    }

    #[test]
    fn a_merged_copy_of_the_same_database_keeps_its_sync_settings() {
        let mut other_phone = database_with(b"mine");
        other_phone.set_sync_settings(&settings("x"), NOW).unwrap();
        let mut mine = database_with(b"mine");
        mine.merge_from(&other_phone).unwrap();
        assert!(mine.sync_entry().is_some());
    }

    #[test]
    fn incomplete_settings_are_refused() {
        let mut database = database();
        let mut incomplete = settings("x");
        incomplete.path = Zeroizing::new(String::new());
        assert!(database.set_sync_settings(&incomplete, NOW).is_err());
        assert!(database.sync_entry().is_none());
    }
}
