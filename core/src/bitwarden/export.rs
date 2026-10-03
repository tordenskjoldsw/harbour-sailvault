//! Bitwarden/Vaultwarden JSON exports: detecting the kind, decrypting
//! password-protected ones and reading the vault. Field names follow
//! `cipher.export.ts` and its siblings in bitwarden/clients
//! (`docs/bitwarden-export.md`).
//!
//! Values are read leniently, as KeePassXC's `BitwardenReader` does with
//! `QVariant::toString`: a missing value, `null`, an object or an array
//! reads as an empty string, and numbers and booleans as their JSON text.

use std::fmt;

use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::enc_string::EncString;
use super::error::{ImportError, Result};
use super::kdf::Kdf;

/// Exports are a few MiB even for large vaults; the bound keeps a crafted
/// file from exhausting the phone. Nesting is bounded by the fixed structure;
/// serde_json skips unknown values without recursion.
pub const MAX_EXPORT_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// Plain JSON; the file itself exposes every secret.
    Unencrypted,
    /// Encrypted with a key derived from an export password.
    PasswordProtected,
    /// Encrypted with the account key, which only the server can unwrap.
    AccountRestricted,
}

/// A string value, wiped when dropped. Empty for `null`, objects and
/// arrays.
#[derive(Default)]
pub struct Text(Zeroizing<String>);

impl Text {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Text(..)")
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct TextVisitor;

        impl<'de> Visitor<'de> for TextVisitor {
            type Value = Text;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Text, E> {
                Ok(Text(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Text, E> {
                Ok(Text(Zeroizing::new(value)))
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Text, E> {
                Ok(Text(Zeroizing::new(value.to_string())))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Text, E> {
                Ok(Text(Zeroizing::new(value.to_string())))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Text, E> {
                Ok(Text(Zeroizing::new(value.to_string())))
            }

            fn visit_f64<E>(self, value: f64) -> std::result::Result<Text, E> {
                Ok(Text(Zeroizing::new(value.to_string())))
            }

            fn visit_unit<E>(self) -> std::result::Result<Text, E> {
                Ok(Text::default())
            }

            fn visit_none<E>(self) -> std::result::Result<Text, E> {
                Ok(Text::default())
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Text, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Text::default())
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Text, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Text::default())
            }
        }

        deserializer.deserialize_any(TextVisitor)
    }
}

/// The fields of a card, identity, SSH key, bank account, driver's license
/// or passport, in file order.
#[derive(Debug, Default)]
pub struct Section(Vec<(String, Text)>);

impl Section {
    /// The value of `key`, empty when it is missing.
    pub fn get(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map_or("", |(_, value)| value.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

impl<'de> Deserialize<'de> for Section {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SectionVisitor;

        impl<'de> Visitor<'de> for SectionVisitor {
            type Value = Section;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Section, A::Error> {
                let mut fields = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Text>()? {
                    fields.push((key, value));
                }
                Ok(Section(fields))
            }
        }

        deserializer.deserialize_map(SectionVisitor)
    }
}

#[derive(Debug, Deserialize)]
pub struct Folder {
    #[serde(default)]
    pub id: Text,
    #[serde(default)]
    pub name: Text,
}

#[derive(Debug, Deserialize)]
pub struct Field {
    #[serde(default)]
    pub name: Text,
    #[serde(default)]
    pub value: Text,
    /// 0 text, 1 hidden, 2 boolean, 3 linked.
    #[serde(default, rename = "type")]
    pub field_type: Text,
}

#[derive(Debug, Deserialize)]
pub struct Uri {
    #[serde(default)]
    pub uri: Text,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    #[serde(default)]
    pub credential_id: Text,
    #[serde(default)]
    pub key_value: Text,
    #[serde(default)]
    pub user_name: Text,
    #[serde(default)]
    pub rp_id: Text,
    #[serde(default)]
    pub user_handle: Text,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    #[serde(default)]
    pub username: Text,
    #[serde(default)]
    pub password: Text,
    #[serde(default)]
    pub totp: Text,
    #[serde(default, deserialize_with = "list")]
    pub uris: Vec<Uri>,
    #[serde(default, deserialize_with = "list")]
    pub fido2_credentials: Vec<Passkey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryItem {
    #[serde(default)]
    pub password: Text,
    #[serde(default)]
    pub last_used_date: Text,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    #[serde(default)]
    pub folder_id: Text,
    #[serde(default, deserialize_with = "list")]
    pub collection_ids: Vec<Text>,
    #[serde(default)]
    pub name: Text,
    #[serde(default)]
    pub notes: Text,
    #[serde(default, deserialize_with = "flag")]
    pub favorite: bool,
    #[serde(default, deserialize_with = "list")]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub login: Option<Login>,
    #[serde(default)]
    pub card: Option<Section>,
    #[serde(default)]
    pub identity: Option<Section>,
    #[serde(default)]
    pub ssh_key: Option<Section>,
    #[serde(default)]
    pub bank_account: Option<Section>,
    #[serde(default)]
    pub drivers_license: Option<Section>,
    #[serde(default)]
    pub passport: Option<Section>,
    #[serde(default, deserialize_with = "list")]
    pub password_history: Vec<PasswordHistoryItem>,
    #[serde(default)]
    pub creation_date: Text,
    #[serde(default)]
    pub revision_date: Text,
}

impl Item {
    /// The folder, or for organization exports the first collection, as
    /// KeePassXC assigns it.
    pub fn folder(&self) -> &str {
        if self.folder_id.is_empty() {
            self.collection_ids.first().map_or("", Text::as_str)
        } else {
            self.folder_id.as_str()
        }
    }
}

/// The content of an export.
#[derive(Debug)]
pub struct Vault {
    /// Folders of a personal export, or collections of an organization
    /// export.
    pub folders: Vec<Folder>,
    pub items: Vec<Item>,
}

#[derive(Deserialize)]
struct RawVault {
    #[serde(default)]
    folders: Option<Vec<Folder>>,
    #[serde(default)]
    collections: Option<Vec<Folder>>,
    #[serde(default)]
    items: Option<Vec<Item>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    #[serde(default, deserialize_with = "flag")]
    encrypted: bool,
    #[serde(default, deserialize_with = "flag")]
    password_protected: bool,
    #[serde(default)]
    salt: Text,
    #[serde(default)]
    kdf_type: Option<u32>,
    #[serde(default)]
    kdf_iterations: Option<u32>,
    #[serde(default)]
    kdf_memory: Option<u32>,
    #[serde(default)]
    kdf_parallelism: Option<u32>,
    #[serde(default, rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: Text,
    #[serde(default)]
    data: Text,
    #[serde(default)]
    items: Option<IgnoredAny>,
}

impl Envelope {
    fn parse(json: &[u8]) -> Result<Self> {
        if json.len() > MAX_EXPORT_SIZE {
            return Err(ImportError::TooLarge);
        }
        serde_json::from_slice(json).map_err(|_| ImportError::NotAnExport)
    }

    fn kind(&self) -> Result<ExportKind> {
        match (self.encrypted, self.password_protected) {
            (false, _) if self.items.is_some() => Ok(ExportKind::Unencrypted),
            (false, _) => Err(ImportError::NotAnExport),
            (true, true) => Ok(ExportKind::PasswordProtected),
            (true, false) => Ok(ExportKind::AccountRestricted),
        }
    }
}

/// Reads only the top level of `json`, so the UI can ask for a password or
/// warn about a plain file before importing.
pub fn export_kind(json: &[u8]) -> Result<ExportKind> {
    Envelope::parse(json)?.kind()
}

/// Reads an export. A password-protected export needs `password` and runs
/// its KDF: call this off the UI thread.
pub fn read_export(json: &[u8], password: Option<&[u8]>) -> Result<Vault> {
    let envelope = Envelope::parse(json)?;
    match envelope.kind()? {
        ExportKind::Unencrypted => parse_vault(json),
        ExportKind::PasswordProtected => {
            let password = password.ok_or(ImportError::PasswordRequired)?;
            let data = decrypt(&envelope, password)?;
            parse_vault(data.as_bytes())
        }
        ExportKind::AccountRestricted => Err(ImportError::AccountRestricted),
    }
}

fn decrypt(envelope: &Envelope, password: &[u8]) -> Result<Zeroizing<String>> {
    let kdf = Kdf::from_export(
        envelope.kdf_type.ok_or(ImportError::InvalidKdfParameters)?,
        envelope
            .kdf_iterations
            .ok_or(ImportError::InvalidKdfParameters)?,
        envelope.kdf_memory,
        envelope.kdf_parallelism,
    )?;
    let key = kdf.derive_export_key(password, envelope.salt.as_str())?;
    let validation: EncString = envelope.enc_key_validation.as_str().parse()?;
    validation.decrypt(&key).map_err(|error| match error {
        ImportError::MacMismatch => ImportError::WrongPassword,
        other => other,
    })?;
    envelope
        .data
        .as_str()
        .parse::<EncString>()?
        .decrypt_to_string(&key)
}

fn parse_vault(json: &[u8]) -> Result<Vault> {
    let raw: RawVault = serde_json::from_slice(json).map_err(|_| ImportError::InvalidJson)?;
    let items = raw.items.ok_or(ImportError::NotAnExport)?;
    Ok(Vault {
        folders: raw.folders.or(raw.collections).unwrap_or_default(),
        items,
    })
}

fn list<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn flag<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_export_kind() {
        let kind = |json: &str| export_kind(json.as_bytes());
        assert_eq!(
            kind(r#"{"encrypted": false, "items": []}"#),
            Ok(ExportKind::Unencrypted)
        );
        assert_eq!(
            kind(r#"{"encrypted": true, "passwordProtected": true}"#),
            Ok(ExportKind::PasswordProtected)
        );
        assert_eq!(
            kind(r#"{"encrypted": true, "data": "2.x|y|z"}"#),
            Ok(ExportKind::AccountRestricted)
        );
        assert_eq!(kind("[1, 2]"), Err(ImportError::NotAnExport));
        assert_eq!(kind("[]"), Err(ImportError::NotAnExport));
        assert_eq!(
            kind(r#"{"encrypted": false}"#),
            Err(ImportError::NotAnExport)
        );
        assert_eq!(kind("not json"), Err(ImportError::NotAnExport));
        assert_eq!(
            read_export(br#"{"encrypted": true}"#, None).map(|_| ()),
            Err(ImportError::AccountRestricted)
        );
        assert_eq!(
            read_export(br#"{"encrypted": true, "passwordProtected": true}"#, None).map(|_| ()),
            Err(ImportError::PasswordRequired)
        );
        assert_eq!(
            read_export(br#"{"encrypted": false}"#, None).map(|_| ()),
            Err(ImportError::NotAnExport)
        );
    }

    #[test]
    fn reads_values_leniently() {
        let vault = read_export(
            br#"{"encrypted": false, "folders": null, "collections": [{"id": "c", "name": "Team"}],
                "items": [{"name": "Card", "notes": null, "favorite": null, "fields": null,
                           "collectionIds": ["c"], "unknown": {"nested": [1]},
                           "card": {"number": "4111", "expMonth": 1, "brand": null,
                                    "extra": {"a": 1}}}]}"#,
            None,
        )
        .unwrap();
        assert_eq!(vault.folders[0].name.as_str(), "Team");
        let item = &vault.items[0];
        assert_eq!(item.folder(), "c");
        assert_eq!(item.notes.as_str(), "");
        assert!(!item.favorite);
        let card = item.card.as_ref().unwrap();
        assert_eq!(card.get("expMonth"), "1");
        assert_eq!(
            card.iter().collect::<Vec<_>>(),
            [
                ("number", "4111"),
                ("expMonth", "1"),
                ("brand", ""),
                ("extra", "")
            ]
        );
    }

    #[test]
    fn rejects_oversized_files_and_skips_deep_nesting_without_recursion() {
        let large = vec![b' '; MAX_EXPORT_SIZE + 1];
        assert_eq!(export_kind(&large), Err(ImportError::TooLarge));
        let levels = 100_000;
        let deep = format!(
            r#"{{"encrypted": false, "items": [{{"name": "x", "notes": {}{}}}]}}"#,
            "[".repeat(levels),
            "]".repeat(levels)
        );
        let vault = read_export(deep.as_bytes(), None).unwrap();
        assert_eq!(vault.items[0].notes.as_str(), "");
    }
}
