use zeroize::Zeroizing;

use super::database::{Database, Entry, Group};
use super::error::Result;

const SEARCHED_FIELDS: [&str; 4] = ["Title", "UserName", "URL", "Notes"];

/// An entry with the group it is in. History entries are not listed.
#[derive(Clone, Copy)]
pub struct ListedEntry<'a> {
    pub entry: Entry<'a>,
    pub group: Group<'a>,
    /// False when the entry is in a group excluded from search, such as the
    /// recycle bin.
    pub searchable: bool,
}

impl Database {
    /// All current entries in document order, depth first.
    pub fn entries(&self) -> Result<Vec<ListedEntry<'_>>> {
        let mut entries = Vec::new();
        collect(self.root_group()?, true, &mut entries);
        Ok(entries)
    }

    /// Entries whose title, user name, URL, notes or tags contain every
    /// whitespace-separated term of `query`, ignoring case. Protected values
    /// are never searched. An empty query matches all searchable entries.
    pub fn search(&self, query: &str) -> Result<Vec<ListedEntry<'_>>> {
        let terms: Vec<Zeroizing<String>> = query
            .split_whitespace()
            .map(|term| Zeroizing::new(term.to_lowercase()))
            .collect();
        Ok(self
            .entries()?
            .into_iter()
            .filter(|listed| listed.searchable && matches(&listed.entry, &terms))
            .collect())
    }
}

fn collect<'a>(group: Group<'a>, parent_searchable: bool, entries: &mut Vec<ListedEntry<'a>>) {
    let searchable = match group
        .element()
        .child("EnableSearching")
        .map(|setting| setting.text())
    {
        Some(setting) if setting.eq_ignore_ascii_case("false") => false,
        Some(setting) if setting.eq_ignore_ascii_case("true") => true,
        _ => parent_searchable,
    };
    entries.extend(group.entries().map(|entry| ListedEntry {
        entry,
        group,
        searchable,
    }));
    for child in group.groups() {
        collect(child, searchable, entries);
    }
}

fn matches(entry: &Entry<'_>, terms: &[Zeroizing<String>]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let mut haystack = Zeroizing::new(String::new());
    for field in entry.fields() {
        if !field.is_protected() && SEARCHED_FIELDS.contains(&field.key().as_str()) {
            haystack.push_str(&field.value().to_lowercase());
            haystack.push('\n');
        }
    }
    haystack.push_str(&entry.tags().to_lowercase());
    terms.iter().all(|term| haystack.contains(term.as_str()))
}
