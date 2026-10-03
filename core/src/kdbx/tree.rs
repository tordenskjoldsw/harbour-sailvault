//! Navigation in the document by paths of child indices from the
//! `KeePassFile` element.

use super::database::{decode_uuid, UUID_LENGTH};
use super::error::{KdbxError, Result};
use super::layout::is_element;
use super::xml::{Element, Node};

// A path of this length (Root, Group) is the root group itself.
pub(super) const ROOT_GROUP_PATH_LENGTH: usize = 2;

pub(super) fn root_mut(document: &mut Element) -> Result<&mut Element> {
    document
        .child_mut("Root")
        .ok_or(KdbxError::InvalidXml("missing root group"))
}

pub(super) fn root_group_mut(document: &mut Element) -> Result<&mut Element> {
    root_mut(document)?
        .child_mut("Group")
        .ok_or(KdbxError::InvalidXml("missing root group"))
}

pub(super) fn group_mut<'a>(
    document: &'a mut Element,
    uuid: &[u8; UUID_LENGTH],
) -> Option<&'a mut Element> {
    let path = group_path(document, uuid)?;
    descend_mut(document, &path)
}

/// Levels of groups in `group`, itself included.
pub(super) fn group_height(group: &Element) -> usize {
    1 + group
        .children_named("Group")
        .map(group_height)
        .max()
        .unwrap_or(0)
}

pub(super) fn contains_group(group: &Element, uuid: &[u8; UUID_LENGTH]) -> bool {
    group.children_named("Group").any(|child| {
        child.child("UUID").and_then(decode_uuid).as_ref() == Some(uuid)
            || contains_group(child, uuid)
    })
}

/// The root group with its path (`Root`, then `Group`) in the document.
pub(super) fn root_group_path(document: &Element) -> Option<(Vec<usize>, &Element)> {
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
pub(super) fn entry_path(document: &Element, uuid: &[u8; UUID_LENGTH]) -> Option<Vec<usize>> {
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
pub(super) fn group_path(document: &Element, uuid: &[u8; UUID_LENGTH]) -> Option<Vec<usize>> {
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

pub(super) fn descend<'a>(element: &'a Element, path: &[usize]) -> Option<&'a Element> {
    path.iter().try_fold(element, |current, &index| {
        match current.children.get(index) {
            Some(Node::Element(child)) => Some(child),
            _ => None,
        }
    })
}

pub(super) fn descend_mut<'a>(element: &'a mut Element, path: &[usize]) -> Option<&'a mut Element> {
    path.iter().try_fold(element, |current, &index| {
        match current.children.get_mut(index) {
            Some(Node::Element(child)) => Some(child),
            _ => None,
        }
    })
}

/// The groups along a path, outermost first.
pub(super) fn groups_on_path<'a>(document: &'a Element, path: &[usize]) -> Vec<&'a Element> {
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

/// The UUID of the group holding the entry at `path`.
pub(super) fn parent_uuid(document: &Element, path: &[usize]) -> Option<[u8; UUID_LENGTH]> {
    groups_on_path(document, path)
        .last()
        .and_then(|group| group.child("UUID"))
        .and_then(decode_uuid)
}

pub(super) fn remove_at(document: &mut Element, path: &[usize]) -> Option<Element> {
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
