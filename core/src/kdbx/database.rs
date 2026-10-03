use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::OuterHeader;
use super::inner_header::{Binary, InnerHeader, ProtectedStream, STREAM_KEY_LENGTH};
use super::key::{CompositeKey, KEY_LENGTH};
use super::payload::{self, PayloadKeys};
use super::xml::{self, Element};
use crate::random;

const UUID_LENGTH: usize = 16;

/// An unlocked KDBX 4 database: the outer header, the inner header with the
/// attachment pool, the complete XML document and the composite key, which
/// every save needs again because the KDF seed changes.
pub struct Database {
    header: OuterHeader,
    inner: InnerHeader,
    document: Element,
    key: CompositeKey,
}

impl Database {
    /// Unlocks a KDBX 4 file. Runs the KDF, so it must not run on the UI
    /// thread.
    pub fn open(data: &[u8], key: CompositeKey) -> Result<Self> {
        let (header, header_length) = OuterHeader::parse(data)?;
        payload::verify_header_hash(data, &header, header_length)?;
        let transformed = header.kdf.transform(&key)?;
        let (inner, document) = decrypt(data, &header, header_length, &transformed)?;
        let database = Self {
            header,
            inner,
            document,
            key,
        };
        database.root_group()?;
        validate_fields(&database.document)?;
        Ok(database)
    }

    /// Serializes the database as a KDBX 4 file with a fresh master seed,
    /// IV, KDF seed and inner stream key, then decrypts the result again and
    /// compares it with the model before returning it. Runs the KDF, so it
    /// must not run on the UI thread.
    pub fn save(&self) -> Result<Vec<u8>> {
        let header = self.header.renewed()?;
        let transformed = header.kdf.transform(&self.key)?;
        let keys = PayloadKeys::derive(&header, &transformed);

        let stream_key = Zeroizing::new(random::array::<STREAM_KEY_LENGTH>()?);
        let mut plaintext = Zeroizing::new(Vec::new());
        self.inner.serialize(&stream_key, &mut plaintext)?;
        xml::write(
            &self.document,
            &mut ProtectedStream::new(stream_key.as_ref()),
            &mut plaintext,
        );

        let mut file = header.bytes.clone();
        payload::write_header_authentication(&header, &keys, &mut file);
        payload::encrypt(&plaintext, &header, &keys, &mut file)?;
        self.verify(&file, &transformed)?;
        Ok(file)
    }

    fn verify(&self, file: &[u8], transformed: &[u8; KEY_LENGTH]) -> Result<()> {
        let (header, header_length) = OuterHeader::parse(file)?;
        payload::verify_header_hash(file, &header, header_length)?;
        let (inner, document) = decrypt(file, &header, header_length, transformed)?;
        if document != self.document || inner.binaries != self.inner.binaries {
            return Err(KdbxError::WriteVerificationFailed);
        }
        Ok(())
    }

    pub fn header(&self) -> &OuterHeader {
        &self.header
    }

    /// The complete XML document, including everything SailVault does not
    /// interpret.
    pub fn document(&self) -> &Element {
        &self.document
    }

    pub fn binaries(&self) -> &[Binary] {
        &self.inner.binaries
    }

    pub fn meta(&self) -> Option<&Element> {
        self.document.child("Meta")
    }

    pub fn root_group(&self) -> Result<Group<'_>> {
        self.document
            .child("Root")
            .and_then(|root| root.child("Group"))
            .map(Group)
            .ok_or(KdbxError::InvalidXml("missing root group"))
    }

    pub fn recycle_bin(&self) -> Option<[u8; UUID_LENGTH]> {
        let meta = self.meta()?;
        if meta
            .child("RecycleBinEnabled")
            .is_some_and(|enabled| xml::parse_bool(&enabled.text()) == Some(false))
        {
            return None;
        }
        decode_uuid(meta.child("RecycleBinUUID")?).filter(|uuid| *uuid != [0; UUID_LENGTH])
    }

    pub fn deleted_objects(&self) -> Vec<DeletedObject> {
        self.document
            .child("Root")
            .and_then(|root| root.child("DeletedObjects"))
            .map(|deleted| {
                deleted
                    .children_named("DeletedObject")
                    .filter_map(|object| {
                        Some(DeletedObject {
                            uuid: decode_uuid(object.child("UUID")?)?,
                            deletion_time: object.child("DeletionTime")?.text().to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn attachment(&self, reference: &Attachment<'_>) -> Option<&Binary> {
        self.inner.binaries.get(reference.pool_index?)
    }
}

/// Authenticates and decrypts the payload with an already transformed key.
fn decrypt(
    data: &[u8],
    header: &OuterHeader,
    header_length: usize,
    transformed: &[u8; KEY_LENGTH],
) -> Result<(InnerHeader, Element)> {
    let keys = PayloadKeys::derive(header, transformed);
    let payload_start = payload::verify_header_hmac(data, header, header_length, &keys)?;
    let plaintext = payload::decrypt(&data[payload_start..], header, &keys)?;

    let (inner, mut stream, xml_start) = InnerHeader::parse(&plaintext)?;
    let document = xml::parse(&plaintext[xml_start..], &mut stream)?;
    if document.name != "KeePassFile" {
        return Err(KdbxError::InvalidXml("unexpected root element"));
    }
    Ok((inner, document))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedObject {
    pub uuid: [u8; UUID_LENGTH],
    pub deletion_time: String,
}

#[derive(Clone, Copy)]
pub struct Group<'a>(&'a Element);

impl<'a> Group<'a> {
    pub fn uuid(&self) -> Option<[u8; UUID_LENGTH]> {
        decode_uuid(self.0.child("UUID")?)
    }

    pub fn name(&self) -> Zeroizing<String> {
        self.0.child("Name").map(Element::text).unwrap_or_default()
    }

    pub fn groups(&self) -> impl Iterator<Item = Group<'a>> {
        self.0.children_named("Group").map(Group)
    }

    pub fn entries(&self) -> impl Iterator<Item = Entry<'a>> {
        self.0.children_named("Entry").map(Entry)
    }

    pub fn element(&self) -> &'a Element {
        self.0
    }
}

#[derive(Clone, Copy)]
pub struct Entry<'a>(&'a Element);

impl<'a> Entry<'a> {
    pub fn uuid(&self) -> Option<[u8; UUID_LENGTH]> {
        decode_uuid(self.0.child("UUID")?)
    }

    /// Each field once, in document order. A repeated key takes the later
    /// value, as in KeePassXC; `Database::open` has already rejected repeats
    /// of a key whose earlier value is not empty.
    pub fn fields(&self) -> impl Iterator<Item = Field<'a>> {
        let mut fields: Vec<Field<'a>> = Vec::new();
        for string in self.0.children_named("String") {
            let (Some(key), Some(value)) = (string.child("Key"), string.child("Value")) else {
                continue;
            };
            let field = Field { key, value };
            match fields
                .iter_mut()
                .find(|existing| existing.key() == field.key())
            {
                Some(existing) => *existing = field,
                None => fields.push(field),
            }
        }
        fields.into_iter()
    }

    pub fn field(&self, key: &str) -> Option<Field<'a>> {
        self.fields().find(|field| *field.key() == key)
    }

    pub fn tags(&self) -> Zeroizing<String> {
        self.0.child("Tags").map(Element::text).unwrap_or_default()
    }

    pub fn history(&self) -> impl Iterator<Item = Entry<'a>> {
        self.0
            .child("History")
            .into_iter()
            .flat_map(|history| history.children_named("Entry").map(Entry))
    }

    pub fn attachments(&self) -> impl Iterator<Item = Attachment<'a>> {
        self.0.children_named("Binary").filter_map(|binary| {
            let value = binary.child("Value")?;
            Some(Attachment {
                name: binary.child("Key")?,
                pool_index: value.attribute("Ref").and_then(|r| r.parse().ok()),
            })
        })
    }

    pub fn element(&self) -> &'a Element {
        self.0
    }
}

#[derive(Clone, Copy)]
pub struct Field<'a> {
    key: &'a Element,
    value: &'a Element,
}

impl Field<'_> {
    pub fn key(&self) -> Zeroizing<String> {
        self.key.text()
    }

    pub fn value(&self) -> Zeroizing<String> {
        self.value.text()
    }

    pub fn is_protected(&self) -> bool {
        self.value.is_protected()
    }
}

#[derive(Clone, Copy)]
pub struct Attachment<'a> {
    name: &'a Element,
    pool_index: Option<usize>,
}

impl Attachment<'_> {
    pub fn name(&self) -> Zeroizing<String> {
        self.name.text()
    }
}

/// Rejects an entry (including history entries) that repeats a field key
/// whose earlier value is not empty, as KeePassXC does ("Duplicate custom
/// attribute found"). Otherwise it would be ambiguous which value is shown,
/// copied and later saved.
pub(crate) fn validate_fields(document: &Element) -> Result<()> {
    let mut pending = vec![document];
    while let Some(element) = pending.pop() {
        if element.name == "Entry" {
            let mut filled_keys: Vec<Zeroizing<String>> = Vec::new();
            for string in element.children_named("String") {
                let (Some(key), Some(value)) = (string.child("Key"), string.child("Value")) else {
                    continue;
                };
                let key = key.text();
                if filled_keys.contains(&key) {
                    return Err(KdbxError::InvalidXml("duplicate field"));
                }
                if !value.text().is_empty() {
                    filled_keys.push(key);
                }
            }
        }
        pending.extend(element.elements());
    }
    Ok(())
}

fn decode_uuid(element: &Element) -> Option<[u8; UUID_LENGTH]> {
    STANDARD.decode(element.text().trim()).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(strings: &str) -> Element {
        let xml = format!(
            "<KeePassFile><Root><Group><Entry>{strings}</Entry></Group></Root></KeePassFile>"
        );
        xml::parse(xml.as_bytes(), &mut ProtectedStream::new(&[0u8; 64])).unwrap()
    }

    fn string(key: &str, value: &str) -> String {
        format!("<String><Key>{key}</Key><Value>{value}</Value></String>")
    }

    #[test]
    fn rejects_repeated_keys_with_a_value() {
        let repeated = document(&(string("Title", "a") + &string("Title", "b")));
        assert_eq!(
            validate_fields(&repeated),
            Err(KdbxError::InvalidXml("duplicate field"))
        );
        let in_history = document(&format!(
            "<History><Entry>{}{}</Entry></History>",
            string("URL", "x"),
            string("URL", "")
        ));
        assert_eq!(
            validate_fields(&in_history),
            Err(KdbxError::InvalidXml("duplicate field"))
        );
    }

    #[test]
    fn an_empty_earlier_value_is_replaced_by_the_later_one() {
        let root =
            document(&(string("Title", "") + &string("UserName", "u") + &string("Title", "kept")));
        assert_eq!(validate_fields(&root), Ok(()));
        let entry = Entry(
            root.child("Root")
                .and_then(|r| r.child("Group"))
                .and_then(|g| g.child("Entry"))
                .unwrap(),
        );
        let keys: Vec<String> = entry.fields().map(|f| f.key().to_string()).collect();
        assert_eq!(keys, ["Title", "UserName"]);
        assert_eq!(*entry.field("Title").unwrap().value(), "kept");
    }
}
