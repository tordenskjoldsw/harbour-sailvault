use std::ffi::{c_char, c_void, CStr};

use super::{read_uuid_out, ListItem, SvDatabase, SvString};
use super::{SV_CANCELLED, SV_COLUMN_GROUP, SV_COLUMN_TITLE, SV_COLUMN_USER_NAME};
use super::{SV_INVALID_ARGUMENT, SV_NOT_FOUND, SV_OK};
use super::{SV_QUALITY_EXCELLENT, SV_QUALITY_GOOD, SV_QUALITY_POOR, SV_QUALITY_WEAK};
use crate::strength::{self, PasswordReport, Quality, EXCELLENT_BITS};

/// The strength estimator: rates zero-terminated UTF-8 text and returns its
/// entropy in bits. It must not keep the pointer or call back into this API.
pub type SvEstimator = unsafe extern "C" fn(password: *const c_char) -> f64;

/// Asked before each estimate of a report; true stops it.
pub type SvCancelled = unsafe extern "C" fn(context: *mut c_void) -> bool;

struct ReportEntry {
    item: ListItem,
    bits: f64,
    quality: Quality,
    shared_with: usize,
}

pub struct SvPasswordReport {
    checked: usize,
    entries: Vec<ReportEntry>,
}

fn quality_code(quality: Quality) -> u32 {
    match quality {
        Quality::Poor => SV_QUALITY_POOR,
        Quality::Weak => SV_QUALITY_WEAK,
        Quality::Good => SV_QUALITY_GOOD,
        Quality::Excellent => SV_QUALITY_EXCELLENT,
    }
}

/// The entropy in bits of the UTF-8 text `password`, or a negative number
/// for invalid arguments. The estimator gets at most the first 256 UTF-16
/// units, zero-terminated, in memory that is wiped; each further unit counts
/// with their average, as in KeePassXC.
///
/// # Safety
///
/// `password` must be null or valid UTF-8 of `password_length` bytes;
/// `estimator` must be safe to call with zero-terminated text.
#[no_mangle]
pub unsafe extern "C" fn sv_password_entropy(
    password: *const u8,
    password_length: usize,
    estimator: Option<SvEstimator>,
) -> f64 {
    let (Some(password), Some(estimator)) = (super::utf8(password, password_length), estimator)
    else {
        return -1.0;
    };
    strength::entropy_bits(password, &mut |text: &CStr| estimator(text.as_ptr()))
}

/// The `SV_QUALITY_*` level of an entropy in bits.
#[no_mangle]
pub extern "C" fn sv_password_quality(bits: f64) -> u32 {
    quality_code(Quality::of(bits))
}

/// The entropy from which a password is `SV_QUALITY_EXCELLENT`.
#[no_mangle]
pub extern "C" fn sv_password_excellent_bits() -> f64 {
    EXCELLENT_BITS
}

/// Rates the password of every current entry outside the recycle bin, except
/// empty ones and entries KeePassXC excludes from its reports, and lists
/// those rated Poor or Weak or sharing their password with other entries.
/// Each password is lent to `estimator` as in `sv_password_entropy` and
/// compared inside; none is in the result. `cancelled`, which may be null,
/// is asked with `context` before each estimate; `SV_CANCELLED` when it
/// returned true.
///
/// # Safety
///
/// `database` must be a live handle that no other thread modifies or frees
/// meanwhile; `estimator` and `cancelled` must be safe to call; `out` valid
/// for one write. Release the report with `sv_password_report_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_database_password_report(
    database: *const SvDatabase,
    estimator: Option<SvEstimator>,
    cancelled: Option<SvCancelled>,
    context: *mut c_void,
    out: *mut *mut SvPasswordReport,
) -> i32 {
    let (Some(database), Some(estimator), Some(out)) = (database.as_ref(), estimator, out.as_mut())
    else {
        return SV_INVALID_ARGUMENT;
    };
    *out = std::ptr::null_mut();
    let report = PasswordReport::of(
        &database.database,
        &mut |text: &CStr| estimator(text.as_ptr()),
        &|| cancelled.is_some_and(|cancelled| cancelled(context)),
    );
    let report = match report {
        Ok(Some(report)) => report,
        Ok(None) => return SV_CANCELLED,
        Err(error) => return super::status(error),
    };
    let entries = report
        .items
        .into_iter()
        .map(|item| ReportEntry {
            item: ListItem {
                uuid: item.uuid,
                is_group: false,
                title: item.title,
                user_name: item.user_name,
                group: item.group,
            },
            bits: item.bits,
            quality: item.quality,
            shared_with: item.shared_with,
        })
        .collect();
    *out = Box::into_raw(Box::new(SvPasswordReport {
        checked: report.checked,
        entries,
    }));
    SV_OK
}

/// Entries the report lists: the weakest first, then those listed only for
/// a shared password.
///
/// # Safety
///
/// `report` must be null or a report that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_length(report: *const SvPasswordReport) -> usize {
    report.as_ref().map_or(0, |report| report.entries.len())
}

/// Entries whose password was rated.
///
/// # Safety
///
/// `report` must be null or a report that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_checked(report: *const SvPasswordReport) -> usize {
    report.as_ref().map_or(0, |report| report.checked)
}

/// Copies the 16-byte UUID of entry `index` into `uuid_out`.
///
/// # Safety
///
/// `report` must be a live report and `uuid_out` valid for writes of 16
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_uuid(
    report: *const SvPasswordReport,
    index: usize,
    uuid_out: *mut u8,
) -> i32 {
    let Some(report) = report.as_ref() else {
        return SV_INVALID_ARGUMENT;
    };
    match report.entries.get(index) {
        Some(entry) => read_uuid_out(uuid_out, &entry.item.uuid),
        None => SV_NOT_FOUND,
    }
}

/// `SV_COLUMN_*`: title, user name, group name.
///
/// # Safety
///
/// `report` must be a live report and `out` valid for one write. Release
/// the string with `sv_string_free`.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_text(
    report: *const SvPasswordReport,
    index: usize,
    column: u32,
    out: *mut SvString,
) -> i32 {
    let (Some(report), Some(out)) = (report.as_ref(), out.as_mut()) else {
        return SV_INVALID_ARGUMENT;
    };
    *out = SvString::EMPTY;
    let Some(entry) = report.entries.get(index) else {
        return SV_NOT_FOUND;
    };
    let text = match column {
        SV_COLUMN_TITLE => &entry.item.title,
        SV_COLUMN_USER_NAME => &entry.item.user_name,
        SV_COLUMN_GROUP => &entry.item.group,
        _ => return SV_INVALID_ARGUMENT,
    };
    *out = SvString::new(text);
    SV_OK
}

/// The entropy of entry `index` in bits, negative for no such entry.
///
/// # Safety
///
/// `report` must be null or a report that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_bits(
    report: *const SvPasswordReport,
    index: usize,
) -> f64 {
    report
        .as_ref()
        .and_then(|report| report.entries.get(index))
        .map_or(-1.0, |entry| entry.bits)
}

/// The `SV_QUALITY_*` level of entry `index`.
///
/// # Safety
///
/// `report` must be null or a report that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_quality(
    report: *const SvPasswordReport,
    index: usize,
) -> u32 {
    report
        .as_ref()
        .and_then(|report| report.entries.get(index))
        .map_or(SV_QUALITY_POOR, |entry| quality_code(entry.quality))
}

/// How many other rated entries have the password of entry `index`.
///
/// # Safety
///
/// `report` must be null or a report that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_shared_with(
    report: *const SvPasswordReport,
    index: usize,
) -> usize {
    report
        .as_ref()
        .and_then(|report| report.entries.get(index))
        .map_or(0, |entry| entry.shared_with)
}

/// # Safety
///
/// `report` must be null or a report from this API that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn sv_password_report_free(report: *mut SvPasswordReport) {
    if !report.is_null() {
        drop(Box::from_raw(report));
    }
}
