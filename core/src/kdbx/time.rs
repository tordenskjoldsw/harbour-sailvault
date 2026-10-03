//! KDBX 4 times: base64 of a little-endian i64 counting seconds from
//! 0001-01-01T00:00:00Z.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdbx_time_counts_from_year_one() {
        assert_eq!(kdbx_time(-UNIX_EPOCH_SECONDS), "AAAAAAAAAAA=");
        // 2026-01-01T10:00:00Z; checked against Python's datetime arithmetic.
        assert_eq!(kdbx_time(1_767_261_600), "oDzo4A4AAAA=");
    }
}
