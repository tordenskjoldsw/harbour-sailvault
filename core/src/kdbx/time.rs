//! KDBX 4 times: base64 of a little-endian i64 counting seconds from
//! 0001-01-01T00:00:00Z. KDBX 3 files store ISO 8601 text instead.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Where the Unix epoch falls on that scale.
const UNIX_EPOCH_SECONDS: i64 = 62_135_596_800;

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

/// Seconds since the Unix epoch of an ISO 8601 time as KDBX 3 files store
/// it, `yyyy-MM-ddTHH:mm:ssZ`, also with fractional seconds, which are
/// dropped, or a `+hh:mm`/`-hh:mm` offset. A time without a zone is local
/// to some unknown machine and is `None`, like anything else.
pub(crate) fn parse_iso_time(text: &str) -> Option<i64> {
    let text = text.trim();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let separators = text.as_bytes();
    if separators.len() < 20
        || separators[4] != b'-'
        || separators[7] != b'-'
        || separators[10] != b'T'
        || separators[13] != b':'
        || separators[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    if year < 1 || !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut zone = &text[19..];
    if let Some(fraction) = zone.strip_prefix('.') {
        let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 {
            return None;
        }
        zone = &fraction[length..];
    }
    let offset = match zone.as_bytes() {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let hours: i64 = zone[1..3].parse().ok()?;
            let minutes: i64 = zone[4..6].parse().ok()?;
            if !zone[1..3]
                .bytes()
                .chain(zone[4..6].bytes())
                .all(|b| b.is_ascii_digit())
                || hours > 23
                || minutes > 59
            {
                return None;
            }
            let offset = hours * 3600 + minutes * 60;
            if *sign == b'+' {
                offset
            } else {
                -offset
            }
        }
        _ => return None,
    };
    let local = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(local - offset)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar
/// (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdbx_time_counts_from_year_one() {
        assert_eq!(kdbx_time(-UNIX_EPOCH_SECONDS), "AAAAAAAAAAA=");
        // 2026-01-01T10:00:00Z; checked against Python's datetime arithmetic.
        assert_eq!(kdbx_time(1_767_261_600), "oDzo4A4AAAA=");
    }

    #[test]
    fn iso_times_match_python_datetime() {
        // Expected values from Python's datetime arithmetic.
        for (text, expected) in [
            ("2026-01-01T10:00:00Z", 1_767_261_600),
            ("2024-02-29T10:30:45Z", 1_709_202_645),
            ("2024-02-29T12:30:45+02:00", 1_709_202_645),
            ("2024-02-29T08:00:45-02:30", 1_709_202_645),
            ("2024-02-29T10:30:45.123Z", 1_709_202_645),
            ("1970-01-01T00:00:00Z", 0),
            ("2000-03-01T00:00:00Z", 951_868_800),
            ("0001-01-01T00:00:00Z", -UNIX_EPOCH_SECONDS),
            ("9999-12-31T23:59:59Z", 253_402_300_799),
        ] {
            assert_eq!(parse_iso_time(text), Some(expected), "{text}");
        }
    }

    #[test]
    fn invalid_or_zoneless_iso_times_are_rejected() {
        for text in [
            "2026-01-01T10:00:00",
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "0000-01-01T00:00:00Z",
            "2026-01-01 10:00:00Z",
            "2026-01-01T10:00:00.Z",
            "2026-01-01T10:00:00+2:00",
            "+026-01-01T10:00:00Z",
            "AAAAAAAAAAA=",
            "",
        ] {
            assert_eq!(parse_iso_time(text), None, "{text}");
        }
    }
}
