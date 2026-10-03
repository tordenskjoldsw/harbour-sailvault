//! Maps an export to KDBX entries the way KeePassXC's `BitwardenReader.cpp`
//! does, so imported entries look like entries KeePassXC imported. Where
//! SailVault differs, `docs/bitwarden-export.md` says why.

use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use zeroize::Zeroizing;

use super::error::{ImportError, Result};
use super::export::{Item, Login, Section, Vault};
use crate::kdbx::{NewEntry, NewField, NewGroup};

/// Deeper folder paths are refused: the KDBX reader bounds XML nesting.
const MAX_FOLDER_DEPTH: usize = 32;
const STANDARD_KEYS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
const CUSTOM_FIELD_HIDDEN: &str = "1";
const OTP_KEY: &str = "otp";
const ADDITIONAL_URL_PREFIX: &str = "KP2A_URL";
const PASSKEY_PEM_START: &str = "-----BEGIN PRIVATE KEY-----";
const PASSKEY_PEM_END: &str = "-----END PRIVATE KEY-----";
const STEAM_PREFIX: &str = "steam://";
const STEAM_DIGITS: u32 = 5;
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u32 = 30;

// Sections with a fixed prefix and the keys whose values are protected.
// Card and identity follow KeePassXC; the card number is protected as well.
// KeePassXC ignores the other four types; SailVault keeps every field.
const CARD: (&str, &[&str]) = ("card_", &["number", "code"]);
const SSH_KEY: (&str, &[&str]) = ("sshKey_", &["privateKey"]);
const BANK_ACCOUNT: (&str, &[&str]) = ("bankAccount_", &["accountNumber", "pin", "iban"]);
const DRIVERS_LICENSE: (&str, &[&str]) = ("driversLicense_", &["licenseNumber"]);
const PASSPORT: (&str, &[&str]) = (
    "passport_",
    &["passportNumber", "nationalIdentificationNumber"],
);
const IDENTITY_EXTRA: [&str; 6] = [
    "company",
    "email",
    "phone",
    "ssn",
    "passportNumber",
    "licenseNumber",
];
const IDENTITY_PROTECTED: [&str; 3] = ["ssn", "passportNumber", "licenseNumber"];

const URL_SAFE_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The export as a group named `name`: folders (or collections) become
/// subgroups, split at `/` like KeePassXC does, and items without a known
/// folder land in the group itself.
pub fn import_group(vault: &Vault, name: &str) -> Result<NewGroup> {
    let mut root = new_group(name);
    let mut folders: HashMap<&str, Vec<usize>> = HashMap::new();
    for folder in &vault.folders {
        let segments: Vec<&str> = folder
            .name
            .as_str()
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.is_empty() {
            continue;
        }
        if segments.len() > MAX_FOLDER_DEPTH {
            return Err(ImportError::FolderTooDeep);
        }
        folders.insert(folder.id.as_str(), group_path(&mut root, &segments));
    }
    for item in &vault.items {
        let path = folders.get(item.folder()).map_or(&[][..], Vec::as_slice);
        descend(&mut root, path).entries.push(map_item(item));
    }
    Ok(root)
}

fn new_group(name: &str) -> NewGroup {
    NewGroup {
        name: Zeroizing::new(name.to_owned()),
        entries: Vec::new(),
        groups: Vec::new(),
    }
}

/// Finds or creates the nested groups for `segments`, as KeePassXC's
/// `createGroup` reuses a group whose path already exists.
fn group_path(root: &mut NewGroup, segments: &[&str]) -> Vec<usize> {
    let mut path = Vec::with_capacity(segments.len());
    let mut group = root;
    for segment in segments {
        let index = match group
            .groups
            .iter()
            .position(|child| child.name.as_str() == *segment)
        {
            Some(index) => index,
            None => {
                group.groups.push(new_group(segment));
                group.groups.len() - 1
            }
        };
        path.push(index);
        group = &mut group.groups[index];
    }
    path
}

fn descend<'a>(root: &'a mut NewGroup, path: &[usize]) -> &'a mut NewGroup {
    path.iter()
        .fold(root, |group, &index| &mut group.groups[index])
}

/// The fields of one entry under construction. Custom keys never replace
/// a field: a taken key gets a numbered suffix.
#[derive(Default)]
struct Fields(Vec<NewField>);

impl Fields {
    fn get(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|field| field.key == key)
            .map_or("", |field| field.value.as_str())
    }

    fn contains(&self, key: &str) -> bool {
        STANDARD_KEYS.contains(&key) || self.0.iter().any(|field| field.key == key)
    }

    /// Sets `key`, replacing its value, as `EntryAttributes::set` does.
    fn set(&mut self, key: &str, value: &str, protected: bool) {
        match self.0.iter_mut().find(|field| field.key == key) {
            Some(field) => {
                field.value = Zeroizing::new(value.to_owned());
                field.protected = protected;
            }
            None => self.0.push(NewField::new(key, value, protected)),
        }
    }

    fn set_if_present(&mut self, key: &str, value: &str, protected: bool) {
        if !value.is_empty() {
            self.set(key, value, protected);
        }
    }

    /// Adds a field under `key`, or under `key_2`, `key_3` and so on when
    /// it is taken. KeePassXC appends five random characters instead.
    fn add_unique(&mut self, key: &str, value: &str, protected: bool) {
        let key = if key.is_empty() { "field" } else { key };
        let mut unique = key.to_owned();
        let mut number = 2;
        while self.contains(&unique) {
            unique = format!("{key}_{number}");
            number += 1;
        }
        self.0.push(NewField::new(unique, value, protected));
    }
}

fn map_item(item: &Item) -> NewEntry {
    let mut fields = Fields::default();
    let mut tags = Vec::new();
    fields.set("Title", item.name.as_str(), false);
    fields.set("Notes", item.notes.as_str(), false);
    if item.favorite {
        tags.push("Favorite".to_owned());
    }
    if let Some(login) = &item.login {
        map_login(login, &mut fields, &mut tags);
    }
    if let Some(identity) = &item.identity {
        map_identity(identity, &mut fields);
    }
    for (section, (prefix, protected)) in [
        (&item.card, CARD),
        (&item.ssh_key, SSH_KEY),
        (&item.bank_account, BANK_ACCOUNT),
        (&item.drivers_license, DRIVERS_LICENSE),
        (&item.passport, PASSPORT),
    ] {
        if let Some(section) = section {
            for (key, value) in section.iter() {
                fields.set_if_present(&format!("{prefix}{key}"), value, protected.contains(&key));
            }
        }
    }
    for field in &item.fields {
        fields.add_unique(
            field.name.as_str(),
            field.value.as_str(),
            field.field_type.as_str() == CUSTOM_FIELD_HIDDEN,
        );
    }

    let created = parse_time(item.creation_date.as_str());
    let modified = parse_time(item.revision_date.as_str());
    let history = item
        .password_history
        .iter()
        .filter(|old| !old.password.is_empty())
        .filter_map(|old| {
            let last_used = parse_time(old.last_used_date.as_str())?;
            let mut snapshot = Fields::default();
            for key in STANDARD_KEYS {
                let value = if key == "Password" {
                    old.password.as_str()
                } else {
                    fields.get(key)
                };
                snapshot.set(key, value, false);
            }
            Some(NewEntry {
                fields: snapshot.0,
                created,
                modified: Some(last_used),
                ..NewEntry::default()
            })
        })
        .collect();
    NewEntry {
        uuid: parse_uuid(item.id.as_str()),
        fields: fields.0,
        tags,
        created,
        modified,
        history,
    }
}

fn map_login(login: &Login, fields: &mut Fields, tags: &mut Vec<String>) {
    fields.set("UserName", login.username.as_str(), false);
    fields.set("Password", login.password.as_str(), false);
    if !login.totp.is_empty() {
        let url = otp_url(
            login.totp.as_str(),
            fields.get("Title"),
            fields.get("UserName"),
        );
        fields.set(OTP_KEY, &url, true);
    }
    for passkey in &login.fido2_credentials {
        if !passkey.credential_id.is_empty() {
            fields.set(
                "KPEX_PASSKEY_CREDENTIAL_ID",
                &credential_id(passkey.credential_id.as_str()),
                true,
            );
        }
        if !passkey.key_value.is_empty() {
            fields.set(
                "KPEX_PASSKEY_PRIVATE_KEY_PEM",
                &private_key_pem(passkey.key_value.as_str()),
                true,
            );
        }
        fields.set("KPEX_PASSKEY_USERNAME", passkey.user_name.as_str(), false);
        fields.set("KPEX_PASSKEY_RELYING_PARTY", passkey.rp_id.as_str(), false);
        fields.set(
            "KPEX_PASSKEY_USER_HANDLE",
            passkey.user_handle.as_str(),
            true,
        );
        if !tags.iter().any(|tag| tag == "Passkey") {
            tags.push("Passkey".to_owned());
        }
    }
    let mut additional = 1;
    for uri in &login.uris {
        if fields.get("URL").is_empty() {
            fields.set("URL", uri.uri.as_str(), false);
        } else {
            fields.set(
                &format!("{ADDITIONAL_URL_PREFIX}_{additional}"),
                uri.uri.as_str(),
                false,
            );
            additional += 1;
        }
    }
}

fn map_identity(identity: &Section, fields: &mut Fields) {
    let joined = |keys: &[&str], separator: &str| {
        Zeroizing::new(
            keys.iter()
                .map(|key| identity.get(key))
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(separator),
        )
    };
    let name = joined(&["title", "firstName", "middleName", "lastName"], " ");
    fields.set_if_present("identity_name", &name, false);
    let address_keys = [
        "address1",
        "address2",
        "address3",
        "city",
        "state",
        "postalCode",
        "country",
    ];
    if address_keys.iter().any(|key| !identity.get(key).is_empty()) {
        let address = Zeroizing::new(format!(
            "{}\n{}, {} {}\n{}",
            joined(&["address1", "address2", "address3"], "\n").as_str(),
            identity.get("city"),
            identity.get("state"),
            identity.get("postalCode"),
            identity.get("country"),
        ));
        fields.set("identity_address", &address, false);
    }
    for key in IDENTITY_EXTRA {
        fields.set_if_present(
            &format!("identity_{key}"),
            identity.get(key),
            IDENTITY_PROTECTED.contains(&key),
        );
    }
    let username = identity.get("username");
    if !username.is_empty() {
        if fields.get("UserName").is_empty() {
            fields.set("UserName", username, false);
        } else {
            fields.set("identity_username", username, false);
        }
    }
}

/// An `otpauth://` URL for the `otp` attribute. URLs are kept as they are;
/// a bare secret becomes the URL KeePassXC's `Totp::writeSettings` writes,
/// and a `steam://` secret its Steam variant.
fn otp_url(totp: &str, title: &str, user_name: &str) -> Zeroizing<String> {
    if totp.starts_with("otpauth://") {
        return Zeroizing::new(totp.to_owned());
    }
    let (secret, digits, encoder) = match totp.strip_prefix(STEAM_PREFIX) {
        Some(secret) => (secret, STEAM_DIGITS, "&encoder=steam"),
        None => (totp, DEFAULT_DIGITS, ""),
    };
    let issuer = if title.is_empty() {
        Zeroizing::new("KeePassXC".to_owned())
    } else {
        percent_encode(title)
    };
    let account = if user_name.is_empty() {
        Zeroizing::new("none".to_owned())
    } else {
        percent_encode(user_name)
    };
    Zeroizing::new(format!(
        "otpauth://totp/{issuer}:{account}?secret={}&period={DEFAULT_PERIOD}&digits={digits}\
         &issuer={issuer}{encoder}",
        percent_encode(&sanitize_base32(secret)).as_str(),
        issuer = issuer.as_str(),
        account = account.as_str(),
    ))
}

/// KeePassXC's `Base32::sanitizeInput`: maps the look-alikes 0, 1 and 8,
/// drops other characters outside the alphabet and pads to 8 characters.
fn sanitize_base32(secret: &str) -> Zeroizing<String> {
    let mut clean = Zeroizing::new(String::with_capacity(secret.len() + 7));
    for character in secret.chars() {
        match character {
            '0' => clean.push('O'),
            '1' => clean.push('L'),
            '8' => clean.push('B'),
            'A'..='Z' | 'a'..='z' | '2'..='7' => clean.push(character),
            _ => {}
        }
    }
    let remainder = clean.len() % 8;
    if matches!(remainder, 2 | 4 | 5 | 7) {
        for _ in remainder..8 {
            clean.push('=');
        }
    }
    clean
}

/// `QUrl::toPercentEncoding`: everything but RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> Zeroizing<String> {
    let mut encoded = Zeroizing::new(String::with_capacity(value.len()));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// KeePassXC stores credential IDs as unpadded base64url. Bitwarden writes
/// a UUID, or `b64.` and base64url for other IDs (`credential-id-utils.ts`),
/// which KeePassXC's importer does not handle.
fn credential_id(value: &str) -> Zeroizing<String> {
    if let Some(encoded) = value.strip_prefix("b64.") {
        return Zeroizing::new(encoded.trim_end_matches('=').to_owned());
    }
    let digits: Vec<u8> = value.bytes().filter(u8::is_ascii_hexdigit).collect();
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        digits
            .chunks_exact(2)
            .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect(),
    );
    Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

/// The base64url PKCS#8 key as the single-line PEM KeePassXC stores; a value
/// that does not decode is kept as it is.
fn private_key_pem(key_value: &str) -> Zeroizing<String> {
    match URL_SAFE_LENIENT.decode(key_value) {
        Ok(key) => {
            let key = Zeroizing::new(key);
            Zeroizing::new(format!(
                "{PASSKEY_PEM_START}{}{PASSKEY_PEM_END}",
                Zeroizing::new(STANDARD.encode(key.as_slice())).as_str()
            ))
        }
        Err(_) => Zeroizing::new(key_value.to_owned()),
    }
}

/// The item ID as a UUID, so a later import of the same item merges into
/// its entry. Bitwarden and Vaultwarden IDs are UUIDs; other IDs give none.
fn parse_uuid(id: &str) -> Option<[u8; 16]> {
    let bytes = id.as_bytes();
    let dashes_at = [8, 13, 18, 23];
    if bytes.len() != 36
        || dashes_at.iter().any(|&index| bytes[index] != b'-')
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| dashes_at.contains(&index) || byte.is_ascii_hexdigit())
    {
        return None;
    }
    let digits: Vec<u8> = bytes.iter().copied().filter(|&b| b != b'-').collect();
    let mut uuid = [0u8; 16];
    for (target, pair) in uuid.iter_mut().zip(digits.chunks_exact(2)) {
        *target = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(uuid)
}

/// Seconds since the Unix epoch for an ISO 8601 date-time such as
/// `2024-01-15T10:20:30.123Z`. A time without offset counts as UTC.
fn parse_time(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "" | "Z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let zone = rest[1..].replace(':', "");
            if zone.len() != 4 || !zone.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let (hours, minutes): (i64, i64) = (zone[..2].parse().ok()?, zone[2..].parse().ok()?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar (Howard
/// Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::read_export;

    fn field<'a>(entry: &'a NewEntry, key: &str) -> Option<(&'a str, bool)> {
        entry
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| (field.value.as_str(), field.protected))
    }

    #[test]
    fn uses_item_ids_as_uuids() {
        assert_eq!(
            parse_uuid("6f0e1d2c-3b4a-4958-8776-655443322110"),
            Some([
                0x6f, 0x0e, 0x1d, 0x2c, 0x3b, 0x4a, 0x49, 0x58, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32,
                0x21, 0x10
            ])
        );
        for invalid in [
            "",
            "6f0e1d2c3b4a49588776655443322110",
            "6f0e1d2c-3b4a-4958-8776-65544332211g",
            "6f0e1d2c-3b4a-4958-8776-6554433221100",
        ] {
            assert_eq!(parse_uuid(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn parses_iso_8601_times() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        // 2026-01-01T10:00:00Z, as in the KDBX time test.
        assert_eq!(parse_time("2026-01-01T10:00:00.123Z"), Some(1_767_261_600));
        assert_eq!(parse_time("2026-01-01T12:00:00+02:00"), Some(1_767_261_600));
        assert_eq!(parse_time("2026-01-01T05:30:00-0430"), Some(1_767_261_600));
        assert_eq!(parse_time("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for invalid in [
            "",
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-01 10:00:00Z",
            "2026-01-01T10:00:00.Z",
            "2026-01-01T10:00:00+2",
            "2026-01-01T24:00:00Z",
            "+026-01-01T10:00:00Z",
        ] {
            assert_eq!(parse_time(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn builds_otp_urls_like_keepassxc() {
        assert_eq!(
            *otp_url("JBSWY3DPEHPK3PXP", "Mail & Co", "alice@example.org"),
            "otpauth://totp/Mail%20%26%20Co:alice%40example.org?secret=JBSWY3DPEHPK3PXP\
             &period=30&digits=6&issuer=Mail%20%26%20Co"
        );
        assert_eq!(
            *otp_url("jbsw y3dp 0018", "", ""),
            "otpauth://totp/KeePassXC:none?secret=jbswy3dpOOLB%3D%3D%3D%3D&period=30&digits=6\
             &issuer=KeePassXC"
        );
        assert_eq!(
            *otp_url("steam://ABCDE", "Steam", "gamer"),
            "otpauth://totp/Steam:gamer?secret=ABCDE%3D%3D%3D&period=30&digits=5\
             &issuer=Steam&encoder=steam"
        );
        let url = "otpauth://totp/GitHub:alice?secret=ABC&issuer=GitHub";
        assert_eq!(*otp_url(url, "x", "y"), url);
    }

    #[test]
    fn converts_passkey_ids_and_keys() {
        assert_eq!(
            *credential_id("6f0e1d2c-3b4a-4958-8776-655443322110"),
            "bw4dLDtKSViHdmVUQzIhEA"
        );
        assert_eq!(*credential_id("b64.AQID"), "AQID");
        assert_eq!(
            *private_key_pem("-_8"),
            "-----BEGIN PRIVATE KEY-----+/8=-----END PRIVATE KEY-----"
        );
        assert_eq!(*private_key_pem("not base64!"), "not base64!");
    }

    #[test]
    fn maps_items_like_keepassxc() {
        let vault = read_export(
            br#"{"encrypted": false,
                "folders": [{"id": "f1", "name": "Work/Mail"}, {"id": "f2", "name": "Work"},
                            {"id": "f3", "name": "/"}],
                "items": [
                  {"folderId": "f1", "type": 1, "name": "Login", "notes": "n", "favorite": true,
                   "creationDate": "2024-01-01T00:00:00Z", "revisionDate": "2025-01-01T00:00:00Z",
                   "login": {"username": "alice", "password": "new", "totp": "ABC",
                             "uris": [{"uri": "https://a"}, {"uri": "https://b"}, {"uri": "https://c"}],
                             "fido2Credentials": [{"credentialId": "b64.AQID", "keyValue": "AQID",
                                                   "userName": "alice", "rpId": "a",
                                                   "userHandle": "h"}]},
                   "fields": [{"name": "PIN", "value": "1234", "type": 1},
                              {"name": "PIN", "value": "5678", "type": 0},
                              {"name": "Password", "value": "x", "type": 0},
                              {"name": null, "value": "v", "type": 0}],
                   "passwordHistory": [{"password": "old", "lastUsedDate": "2024-06-01T00:00:00Z"},
                                       {"password": "", "lastUsedDate": "2024-07-01T00:00:00Z"},
                                       {"password": "undated", "lastUsedDate": null}]},
                  {"folderId": "f2", "type": 4, "name": "Me",
                   "identity": {"title": "Dr", "firstName": "Ann", "lastName": "Lee",
                                "address1": "Main St 1", "city": "Town", "state": "ST",
                                "postalCode": "123", "country": "DE", "ssn": "999",
                                "email": "ann@example.org", "username": "ann"}},
                  {"folderId": "gone", "type": 3, "name": "Card",
                   "card": {"cardholderName": "Ann", "number": "4111", "code": "123",
                            "brand": null}},
                  {"folderId": "f3", "type": 5, "name": "Key",
                   "sshKey": {"privateKey": "-----BEGIN-----", "publicKey": "ssh-ed25519 AAAA",
                              "keyFingerprint": "SHA256:x"}},
                  {"type": 6, "name": "Bank",
                   "bankAccount": {"bankName": "Bank", "iban": "DE00", "pin": "0000"}}
                ]}"#,
            None,
        )
        .unwrap();
        let group = import_group(&vault, "Bitwarden import").unwrap();
        assert_eq!(group.name.as_str(), "Bitwarden import");
        assert_eq!(group.groups.len(), 1);
        let work = &group.groups[0];
        assert_eq!(work.name.as_str(), "Work");
        assert_eq!(work.groups[0].name.as_str(), "Mail");

        let login = &work.groups[0].entries[0];
        assert_eq!(field(login, "Title"), Some(("Login", false)));
        assert_eq!(field(login, "URL"), Some(("https://a", false)));
        assert_eq!(field(login, "KP2A_URL_1"), Some(("https://b", false)));
        assert_eq!(field(login, "KP2A_URL_2"), Some(("https://c", false)));
        assert_eq!(
            field(login, "otp"),
            Some((
                "otpauth://totp/Login:alice?secret=ABC&period=30&digits=6\
                 &issuer=Login",
                true
            ))
        );
        assert_eq!(
            field(login, "KPEX_PASSKEY_CREDENTIAL_ID"),
            Some(("AQID", true))
        );
        assert_eq!(field(login, "KPEX_PASSKEY_USER_HANDLE"), Some(("h", true)));
        assert_eq!(field(login, "PIN"), Some(("1234", true)));
        assert_eq!(field(login, "PIN_2"), Some(("5678", false)));
        assert_eq!(field(login, "Password_2"), Some(("x", false)));
        assert_eq!(field(login, "field"), Some(("v", false)));
        assert_eq!(login.tags, ["Favorite", "Passkey"]);
        assert_eq!(login.created, Some(1_704_067_200));
        assert_eq!(login.modified, Some(1_735_689_600));
        assert_eq!(login.history.len(), 1);
        let old = &login.history[0];
        assert_eq!(field(old, "Password"), Some(("old", false)));
        assert_eq!(field(old, "UserName"), Some(("alice", false)));
        assert_eq!(old.modified, Some(1_717_200_000));
        assert_eq!(old.created, login.created);
        assert!(field(old, "otp").is_none());

        let identity = &work.entries[0];
        assert_eq!(
            field(identity, "identity_name"),
            Some(("Dr Ann Lee", false))
        );
        assert_eq!(
            field(identity, "identity_address"),
            Some(("Main St 1\nTown, ST 123\nDE", false))
        );
        assert_eq!(field(identity, "identity_ssn"), Some(("999", true)));
        assert_eq!(field(identity, "UserName"), Some(("ann", false)));
        assert!(field(identity, "identity_company").is_none());

        let titles: Vec<&str> = group
            .entries
            .iter()
            .map(|entry| field(entry, "Title").unwrap().0)
            .collect();
        assert_eq!(titles, ["Card", "Key", "Bank"]);
        let card = &group.entries[0];
        assert_eq!(field(card, "card_number"), Some(("4111", true)));
        assert_eq!(field(card, "card_code"), Some(("123", true)));
        assert_eq!(field(card, "card_cardholderName"), Some(("Ann", false)));
        assert!(field(card, "card_brand").is_none());
        let key = &group.entries[1];
        assert_eq!(
            field(key, "sshKey_privateKey"),
            Some(("-----BEGIN-----", true))
        );
        assert_eq!(
            field(key, "sshKey_publicKey"),
            Some(("ssh-ed25519 AAAA", false))
        );
        let bank = &group.entries[2];
        assert_eq!(field(bank, "bankAccount_iban"), Some(("DE00", true)));
        assert_eq!(field(bank, "bankAccount_bankName"), Some(("Bank", false)));
    }

    #[test]
    fn refuses_folder_paths_deeper_than_the_kdbx_reader_reads() {
        let deep = "a/".repeat(MAX_FOLDER_DEPTH + 1);
        let json = format!(
            r#"{{"encrypted": false, "folders": [{{"id": "f", "name": "{deep}"}}], "items": []}}"#
        );
        let vault = read_export(json.as_bytes(), None).unwrap();
        assert_eq!(
            import_group(&vault, "x").map(|_| ()),
            Err(ImportError::FolderTooDeep)
        );
    }
}
