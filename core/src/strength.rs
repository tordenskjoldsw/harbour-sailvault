//! Password strength: what the estimator gets, the quality levels, and the
//! report over all entries.
//!
//! The estimator is not part of the core; the caller passes it in. The core
//! decides what it sees: at most the first `ESTIMATED_UNITS` of a password,
//! zero-terminated, in memory that is wiped. Bounds, levels and the
//! extrapolation for longer passwords follow KeePassXC (`PasswordHealth`),
//! so both rate a password the same.

use std::ffi::CStr;

use zeroize::Zeroizing;

use crate::kdbx::{Database, Entry, Group, Result};

const UUID_LENGTH: usize = 16;

/// UTF-16 code units of a password the estimator rates, the unit KeePassXC
/// counts in. Each further unit counts with the average of these.
pub const ESTIMATED_UNITS: usize = 256;

const WEAK_BITS: f64 = 40.0;
const GOOD_BITS: f64 = 75.0;
pub const EXCELLENT_BITS: f64 = 100.0;

/// KeePassXC marks an entry it leaves out of its reports with the KDBX 4.1
/// element `QualityCheck` set to false; older versions used this entry
/// CustomData key with the value true.
const QUALITY_CHECK: &str = "QualityCheck";
const LEGACY_EXCLUSION_KEY: &str = "KnownBad";

/// Rates zero-terminated UTF-8 text and returns its entropy in bits.
pub type Estimator<'a> = dyn FnMut(&CStr) -> f64 + 'a;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quality {
    Poor,
    Weak,
    Good,
    Excellent,
}

impl Quality {
    pub fn of(bits: f64) -> Self {
        if bits < WEAK_BITS {
            Self::Poor
        } else if bits < GOOD_BITS {
            Self::Weak
        } else if bits < EXCELLENT_BITS {
            Self::Good
        } else {
            Self::Excellent
        }
    }
}

/// The entropy of `password` in bits. The estimator gets the text up to the
/// first zero byte, where a C string ends anyway, and of that at most
/// `ESTIMATED_UNITS`.
pub fn entropy_bits(password: &str, estimate: &mut Estimator<'_>) -> f64 {
    let text = password.split('\0').next().unwrap_or_default();
    let mut rated_units = 0;
    let mut rated_bytes = 0;
    let mut further_units = 0;
    for character in text.chars() {
        let units = character.len_utf16();
        if further_units == 0 && rated_units + units <= ESTIMATED_UNITS {
            rated_units += units;
            rated_bytes += character.len_utf8();
        } else {
            further_units += units;
        }
    }
    if rated_bytes == 0 {
        return 0.0;
    }
    // Sized once, so growing never leaves an unwiped copy behind.
    let mut lent = Zeroizing::new(Vec::with_capacity(rated_bytes + 1));
    lent.extend_from_slice(&text.as_bytes()[..rated_bytes]);
    lent.push(0);
    let Ok(lent) = CStr::from_bytes_with_nul(&lent) else {
        return 0.0;
    };
    let bits = estimate(lent);
    // The estimator is foreign code; nothing it returns may poison a sum.
    if !bits.is_finite() || bits <= 0.0 {
        return 0.0;
    }
    bits + bits / ESTIMATED_UNITS as f64 * further_units as f64
}

/// An entry the report lists: its password is Poor or Weak, or other
/// entries use the same one.
pub struct ReportItem {
    pub uuid: [u8; UUID_LENGTH],
    pub title: Zeroizing<String>,
    pub user_name: Zeroizing<String>,
    pub group: Zeroizing<String>,
    pub bits: f64,
    pub quality: Quality,
    /// How many other rated entries have the same password.
    pub shared_with: usize,
}

pub struct PasswordReport {
    /// Entries whose password was rated.
    pub checked: usize,
    /// The weakest first; entries listed only for a shared password last.
    pub items: Vec<ReportItem>,
}

struct Rated<'a> {
    entry: Entry<'a>,
    group: Group<'a>,
    password: Zeroizing<String>,
    bits: f64,
    shared_with: usize,
}

impl PasswordReport {
    /// Rates the password of every current entry outside the recycle bin
    /// that has one and that KeePassXC does not exclude from its reports.
    /// `cancelled` is asked before each estimate; `None` when it said yes.
    /// Passwords are compared for reuse here, and nothing of them is in the
    /// result.
    pub fn of(
        database: &Database,
        estimate: &mut Estimator<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Self>> {
        let mut entries = Vec::new();
        collect(database.root_group()?, database.recycle_bin(), &mut entries);

        let mut rated = Vec::new();
        for (entry, group) in entries {
            if is_excluded(entry) {
                continue;
            }
            let password = field_text(entry, "Password");
            if password.is_empty() {
                continue;
            }
            if cancelled() {
                return Ok(None);
            }
            let bits = entropy_bits(&password, estimate);
            rated.push(Rated {
                entry,
                group,
                password,
                bits,
                shared_with: 0,
            });
        }
        count_shared(&mut rated);

        let checked = rated.len();
        let mut items: Vec<ReportItem> = rated
            .iter()
            .filter(|rated| Quality::of(rated.bits) <= Quality::Weak || rated.shared_with > 0)
            .filter_map(|rated| {
                Some(ReportItem {
                    uuid: rated.entry.uuid()?,
                    title: field_text(rated.entry, "Title"),
                    user_name: field_text(rated.entry, "UserName"),
                    group: rated.group.name(),
                    bits: rated.bits,
                    quality: Quality::of(rated.bits),
                    shared_with: rated.shared_with,
                })
            })
            .collect();
        items.sort_by(|a, b| {
            let listed_for_sharing = |item: &ReportItem| item.quality > Quality::Weak;
            listed_for_sharing(a)
                .cmp(&listed_for_sharing(b))
                .then(a.bits.total_cmp(&b.bits))
        });
        Ok(Some(Self { checked, items }))
    }
}

fn collect<'a>(
    group: Group<'a>,
    recycle_bin: Option<[u8; UUID_LENGTH]>,
    entries: &mut Vec<(Entry<'a>, Group<'a>)>,
) {
    if recycle_bin.is_some() && group.uuid() == recycle_bin {
        return;
    }
    entries.extend(group.entries().map(|entry| (entry, group)));
    for child in group.groups() {
        collect(child, recycle_bin, entries);
    }
}

fn field_text(entry: Entry<'_>, key: &str) -> Zeroizing<String> {
    entry
        .field(key)
        .map(|field| field.value())
        .unwrap_or_default()
}

fn is_excluded(entry: Entry<'_>) -> bool {
    let element = entry.element();
    let quality_check_off = element
        .child(QUALITY_CHECK)
        .is_some_and(|check| check.text().trim().eq_ignore_ascii_case("false"));
    let marked_known_bad = element.child("CustomData").is_some_and(|data| {
        data.children_named("Item").any(|item| {
            item.child("Key")
                .is_some_and(|key| *key.text() == LEGACY_EXCLUSION_KEY)
                && item
                    .child("Value")
                    .is_some_and(|value| value.text().trim().eq_ignore_ascii_case("true"))
        })
    });
    quality_check_off || marked_known_bad
}

/// Sets `shared_with` by sorting positions, so no password is copied.
fn count_shared(rated: &mut [Rated<'_>]) {
    let mut order: Vec<usize> = (0..rated.len()).collect();
    order.sort_unstable_by(|&a, &b| rated[a].password.as_str().cmp(rated[b].password.as_str()));
    let mut start = 0;
    while start < order.len() {
        let mut end = start + 1;
        while end < order.len() && *rated[order[end]].password == *rated[order[start]].password {
            end += 1;
        }
        for &position in &order[start..end] {
            rated[position].shared_with = end - start - 1;
        }
        start = end;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::kdbx::{CompositeKey, Element, KdfLevel, Node};

    const NOW: i64 = 1_767_261_600;

    /// Rates one bit per byte it is given and records what it saw.
    fn by_length(seen: &mut Vec<Vec<u8>>) -> impl FnMut(&CStr) -> f64 + '_ {
        |text| {
            seen.push(text.to_bytes().to_vec());
            text.to_bytes().len() as f64
        }
    }

    fn database() -> Database {
        let key = CompositeKey::new(Some(b"test"), None).unwrap();
        Database::create(key, "Test", KdfLevel::Standard, NOW).unwrap()
    }

    fn add(database: &mut Database, title: &str, password: &str) -> [u8; UUID_LENGTH] {
        let root = database.root_group().unwrap().uuid().unwrap();
        database
            .add_entry(&root, &[("Title", title), ("Password", password)], NOW)
            .unwrap()
    }

    fn text_element(name: &str, text: &str) -> Element {
        Element {
            name: name.to_owned(),
            attributes: Vec::new(),
            children: vec![Node::Text(Zeroizing::new(text.to_owned()))],
        }
    }

    fn entry_mut<'a>(element: &'a mut Element, title: &str) -> Option<&'a mut Element> {
        let is_entry = element.name == "Entry"
            && element.children_named("String").any(|field| {
                field.child("Key").is_some_and(|key| *key.text() == "Title")
                    && field
                        .child("Value")
                        .is_some_and(|value| *value.text() == title)
            });
        if is_entry {
            return Some(element);
        }
        element.children.iter_mut().find_map(|child| match child {
            Node::Element(child) => entry_mut(child, title),
            Node::Text(_) => None,
        })
    }

    fn report(database: &Database) -> PasswordReport {
        let mut seen = Vec::new();
        let mut estimate = by_length(&mut seen);
        PasswordReport::of(database, &mut estimate, &|| false)
            .unwrap()
            .unwrap()
    }

    fn titles(report: &PasswordReport) -> Vec<&str> {
        report
            .items
            .iter()
            .map(|item| item.title.as_str())
            .collect()
    }

    #[test]
    fn quality_levels_are_those_of_keepassxc() {
        assert_eq!(Quality::of(0.0), Quality::Poor);
        assert_eq!(Quality::of(39.9), Quality::Poor);
        assert_eq!(Quality::of(40.0), Quality::Weak);
        assert_eq!(Quality::of(74.9), Quality::Weak);
        assert_eq!(Quality::of(75.0), Quality::Good);
        assert_eq!(Quality::of(99.9), Quality::Good);
        assert_eq!(Quality::of(100.0), Quality::Excellent);
    }

    #[test]
    fn the_estimator_gets_the_password_zero_terminated() {
        let mut seen = Vec::new();
        assert_eq!(entropy_bits("geheim", &mut by_length(&mut seen)), 6.0);
        assert_eq!(seen, [b"geheim".to_vec()]);
    }

    #[test]
    fn an_empty_password_is_not_estimated() {
        let mut seen = Vec::new();
        assert_eq!(entropy_bits("", &mut by_length(&mut seen)), 0.0);
        assert!(seen.is_empty());
    }

    #[test]
    fn text_after_a_zero_byte_never_reaches_the_estimator() {
        let mut seen = Vec::new();
        assert_eq!(entropy_bits("abc\0secret", &mut by_length(&mut seen)), 3.0);
        assert_eq!(seen, [b"abc".to_vec()]);
    }

    #[test]
    fn a_long_password_is_cut_and_the_rest_counts_with_the_average() {
        let password = "a".repeat(300);
        let mut seen = Vec::new();
        let bits = entropy_bits(&password, &mut by_length(&mut seen));
        assert_eq!(seen, [vec![b'a'; 256]]);
        // 256 bits for the rated part, one more for each of the other 44.
        assert_eq!(bits, 300.0);
    }

    #[test]
    fn the_cut_counts_utf16_units_and_never_splits_a_character() {
        // Each of these is two UTF-16 units and four UTF-8 bytes, so 128 of
        // them fill the limit; with one unit before them only 127 fit.
        let astral = "\u{1F512}";
        let mut seen = Vec::new();
        entropy_bits(&astral.repeat(130), &mut by_length(&mut seen));
        entropy_bits(
            &format!("x{}", astral.repeat(130)),
            &mut by_length(&mut seen),
        );
        assert_eq!(seen[0].len(), 128 * 4);
        assert_eq!(seen[1].len(), 1 + 127 * 4);
        assert!(std::str::from_utf8(&seen[1]).is_ok());
    }

    #[test]
    fn a_result_that_is_not_a_positive_number_counts_as_zero() {
        for broken in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            assert_eq!(entropy_bits("geheim", &mut |_| broken), 0.0);
        }
    }

    #[test]
    fn lists_weak_passwords_weakest_first() {
        let mut database = database();
        add(&mut database, "Weak", &"w".repeat(50));
        add(&mut database, "Strong", &"s".repeat(120));
        add(&mut database, "Poor", "pin1");
        add(&mut database, "No password", "");

        let report = report(&database);
        assert_eq!(report.checked, 3);
        assert_eq!(titles(&report), ["Poor", "Weak"]);
        assert_eq!(report.items[0].quality, Quality::Poor);
        assert_eq!(report.items[0].bits, 4.0);
        assert_eq!(report.items[1].quality, Quality::Weak);
        assert_eq!(*report.items[0].group, "Root");
    }

    #[test]
    fn lists_shared_passwords_after_the_weak_ones() {
        let mut database = database();
        let shared = "x".repeat(110);
        add(&mut database, "Shared one", &shared);
        add(&mut database, "Unique", &"u".repeat(111));
        add(&mut database, "Shared two", &shared);
        add(&mut database, "Shared three", &shared);
        add(&mut database, "Poor twin one", "same");
        add(&mut database, "Poor twin two", "same");

        let report = report(&database);
        assert_eq!(report.checked, 6);
        assert_eq!(
            titles(&report),
            [
                "Poor twin one",
                "Poor twin two",
                "Shared one",
                "Shared two",
                "Shared three"
            ]
        );
        assert_eq!(report.items[0].shared_with, 1);
        assert_eq!(report.items[2].shared_with, 2);
        assert_eq!(report.items[2].quality, Quality::Excellent);
    }

    #[test]
    fn skips_the_recycle_bin() {
        let mut database = database();
        let deleted = add(&mut database, "Deleted", "pin1");
        add(&mut database, "Kept", "pin2");
        let removed_for_good = database.delete_entry(&deleted, NOW).unwrap();
        assert!(!removed_for_good);

        let report = report(&database);
        assert_eq!(report.checked, 1);
        assert_eq!(titles(&report), ["Kept"]);
    }

    #[test]
    fn skips_entries_keepassxc_excludes_from_its_reports() {
        let mut database = database();
        add(&mut database, "Quality check off", "pin1");
        add(&mut database, "Known bad", "pin1");
        add(&mut database, "Quality check on", "pin3");
        add(&mut database, "Rated", "pin4");

        let document = database.document_mut();
        entry_mut(document, "Quality check off")
            .unwrap()
            .children
            .push(Node::Element(text_element("QualityCheck", "False")));
        entry_mut(document, "Quality check on")
            .unwrap()
            .children
            .push(Node::Element(text_element("QualityCheck", "True")));
        let item = Element {
            name: "Item".to_owned(),
            attributes: Vec::new(),
            children: vec![
                Node::Element(text_element("Key", "KnownBad")),
                Node::Element(text_element("Value", "true")),
            ],
        };
        entry_mut(document, "Known bad")
            .unwrap()
            .children
            .push(Node::Element(Element {
                name: "CustomData".to_owned(),
                attributes: Vec::new(),
                children: vec![Node::Element(item)],
            }));

        let report = report(&database);
        assert_eq!(report.checked, 2);
        assert_eq!(titles(&report), ["Quality check on", "Rated"]);
        // The excluded entries have the same password and are not counted
        // as sharing it either.
        assert!(report.items.iter().all(|item| item.shared_with == 0));
    }

    #[test]
    fn stops_before_the_next_estimate_when_cancelled() {
        let mut database = database();
        for index in 0..5 {
            add(&mut database, &format!("Entry {index}"), "pin1");
        }
        let estimates = Cell::new(0);
        let mut estimate = |_: &CStr| {
            estimates.set(estimates.get() + 1);
            4.0
        };
        let report =
            PasswordReport::of(&database, &mut estimate, &|| estimates.get() == 2).unwrap();
        assert!(report.is_none());
        assert_eq!(estimates.get(), 2);
    }
}
