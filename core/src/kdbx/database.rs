use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use super::create::KdfLevel;
use super::error::{KdbxError, Result};
use super::header::OuterHeader;
use super::inner_header::{Binary, InnerHeader, ProtectedStream, STREAM_KEY_LENGTH};
use super::kdbx3;
use super::key::{CompositeKey, KEY_LENGTH};
use super::payload::{self, PayloadKeys};
use super::xml::{self, Element, Node};
use crate::random;
use crate::secret::SecretBuffer;

pub(crate) const UUID_LENGTH: usize = 16;

/// An unlocked KDBX 4 database: the outer header, the inner header with the
/// attachment pool, the complete XML document and the composite key, which
/// every save needs again because the KDF seed changes.
pub struct Database {
    header: OuterHeader,
    inner: InnerHeader,
    document: Element,
    key: CompositeKey,
    from_kdbx3: bool,
}

impl Database {
    /// Unlocks a KDBX 4 file, or a KDBX 3 file, which becomes a KDBX 4
    /// database. Runs the KDF, so it must not run on the UI thread.
    pub fn open(data: &[u8], key: CompositeKey) -> Result<Self> {
        if super::header::version(data)?.0 == kdbx3::MAJOR_VERSION {
            return kdbx3::open(data, key);
        }
        let (header, header_length) = OuterHeader::parse(data)?;
        payload::verify_header_hash(data, &header, header_length)?;
        let transformed = header.kdf.transform(&key)?;
        let (inner, document) = decrypt(data, &header, header_length, &transformed)?;
        Self::from_parts(header, inner, document, key)
    }

    /// A database from its parts, checked like an opened one.
    pub(super) fn from_parts(
        header: OuterHeader,
        inner: InnerHeader,
        document: Element,
        key: CompositeKey,
    ) -> Result<Self> {
        let database = Self {
            header,
            inner,
            document,
            key,
            from_kdbx3: false,
        };
        database.root_group()?;
        validate_fields(&database.document)?;
        Ok(database)
    }

    /// A database converted from a KDBX 3 file, checked like an opened one.
    pub(super) fn converted_from_kdbx3(
        header: OuterHeader,
        inner: InnerHeader,
        document: Element,
        key: CompositeKey,
    ) -> Result<Self> {
        let mut database = Self::from_parts(header, inner, document, key)?;
        database.from_kdbx3 = true;
        Ok(database)
    }

    /// True when the database was read from a KDBX 3 file; it is saved as
    /// KDBX 4.
    pub fn from_kdbx3(&self) -> bool {
        self.from_kdbx3
    }

    /// Switches the key derivation to Argon2id at `level` from the next
    /// save on.
    pub fn set_kdf_level(&mut self, level: KdfLevel) {
        self.header.kdf = level.parameters();
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
        let attachment_bytes: usize = self.inner.binaries.iter().map(|b| b.data.len()).sum();
        let mut plaintext = SecretBuffer::with_capacity(attachment_bytes + (1 << 20));
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

    pub(crate) fn document_mut(&mut self) -> &mut Element {
        &mut self.document
    }

    pub fn binaries(&self) -> &[Binary] {
        &self.inner.binaries
    }

    pub(super) fn binaries_mut(&mut self) -> &mut Vec<Binary> {
        &mut self.inner.binaries
    }

    /// Takes a KDBX 4.1 feature merged from another copy along: the file is
    /// saved as 4.1 then, as KeePassXC saves it.
    pub(super) fn raise_minor_version(&mut self, minor_version: u16) {
        self.header.minor_version = self.header.minor_version.max(minor_version);
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

    /// The current entry with `uuid`, wherever it is.
    pub fn entry(&self, uuid: &[u8; UUID_LENGTH]) -> Option<Entry<'_>> {
        fn search<'a>(group: Group<'a>, uuid: &[u8; UUID_LENGTH]) -> Option<Entry<'a>> {
            group
                .entries()
                .find(|entry| entry.uuid().as_ref() == Some(uuid))
                .or_else(|| group.groups().find_map(|child| search(child, uuid)))
        }
        search(self.root_group().ok()?, uuid)
    }

    /// The group with `uuid`, wherever it is.
    pub fn group(&self, uuid: &[u8; UUID_LENGTH]) -> Option<Group<'_>> {
        fn search<'a>(group: Group<'a>, uuid: &[u8; UUID_LENGTH]) -> Option<Group<'a>> {
            if group.uuid().as_ref() == Some(uuid) {
                return Some(group);
            }
            group.groups().find_map(|child| search(child, uuid))
        }
        search(self.root_group().ok()?, uuid)
    }

    /// `Meta/RecycleBinEnabled`, true when missing, as in KeePassXC.
    pub fn recycle_bin_enabled(&self) -> bool {
        self.meta()
            .and_then(|meta| meta.child("RecycleBinEnabled"))
            .and_then(|enabled| xml::parse_bool(&enabled.text()))
            != Some(false)
    }

    /// The recycle bin group, if enabled and present.
    pub fn recycle_bin(&self) -> Option<[u8; UUID_LENGTH]> {
        if !self.recycle_bin_enabled() {
            return None;
        }
        decode_uuid(self.meta()?.child("RecycleBinUUID")?).filter(|uuid| *uuid != [0; UUID_LENGTH])
    }

    /// The recycle bin, if enabled, set and present as a group.
    pub fn existing_recycle_bin(&self) -> Option<[u8; UUID_LENGTH]> {
        self.recycle_bin().filter(|bin| self.group(bin).is_some())
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

    /// Removes attachments that no entry or history item references any
    /// more and renumbers the references, as KeePassXC rebuilds its pool on
    /// every save. Without this, a deleted attachment would stay in the file.
    pub(super) fn drop_unused_binaries(&mut self) {
        let mut used = vec![false; self.inner.binaries.len()];
        for_each_binary_ref(&mut self.document, &mut |reference| {
            if let Some(used) = reference.parse().ok().and_then(|i: usize| used.get_mut(i)) {
                *used = true;
            }
        });
        if used.iter().all(|&used| used) {
            return;
        }
        let mut new_index = Vec::with_capacity(used.len());
        let mut kept = 0usize;
        for &used in &used {
            new_index.push(kept);
            kept += usize::from(used);
        }
        for_each_binary_ref(&mut self.document, &mut |reference| {
            if let Some(&index) = reference.parse().ok().and_then(|i: usize| new_index.get(i)) {
                *reference = index.to_string();
            }
        });
        let mut used = used.into_iter();
        self.inner
            .binaries
            .retain(|_| used.next().expect("one flag per attachment"));
    }
}

/// Calls `visit` with the `Ref` attribute of every attachment of every entry
/// and history item.
fn for_each_binary_ref(element: &mut Element, visit: &mut impl FnMut(&mut String)) {
    if element.name == "Binary" {
        if let Some((_, reference)) = element
            .child_mut("Value")
            .and_then(|value| value.attributes.iter_mut().find(|(key, _)| key == "Ref"))
        {
            visit(reference);
        }
        return;
    }
    for child in &mut element.children {
        if let Node::Element(child) = child {
            for_each_binary_ref(child, visit);
        }
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

    /// `LastModificationTime` in seconds since the Unix epoch.
    pub fn modification_time(&self) -> Option<i64> {
        let time = super::layout::time_text(self.0, "LastModificationTime")?;
        super::time::parse_kdbx_time(&time)
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

pub(crate) fn decode_uuid(element: &Element) -> Option<[u8; UUID_LENGTH]> {
    // Every tree search decodes UUIDs, so the usual single text node is
    // decoded without allocating. The buffer leaves room for the decoder's
    // length estimate of padded base64.
    let mut decoded = [0u8; UUID_LENGTH + 8];
    let length = match element.children.as_slice() {
        [Node::Text(text)] => STANDARD.decode_slice(text.trim(), &mut decoded),
        _ => STANDARD.decode_slice(element.text().trim(), &mut decoded),
    }
    .ok()?;
    decoded[..length].try_into().ok()
}

pub(crate) fn encode_uuid(uuid: &[u8; UUID_LENGTH]) -> String {
    STANDARD.encode(uuid)
}

#[cfg(test)]
impl Database {
    /// A database around a parsed document, for tests of tree edits.
    pub(crate) fn from_document(document: Element) -> Self {
        use super::header::{Cipher, Compression};
        use super::kdf::KdfParameters;
        Self {
            header: OuterHeader {
                minor_version: 1,
                cipher: Cipher::Aes256,
                compression: Compression::Gzip,
                kdf: KdfParameters::AesKdf {
                    rounds: 1,
                    seed: [0; 32],
                },
                master_seed: [0; 32],
                encryption_iv: vec![0; 16],
                public_custom_data: None,
                bytes: Vec::new(),
            },
            inner: InnerHeader {
                binaries: Vec::new(),
            },
            document,
            key: CompositeKey::new(Some(b"test"), None).expect("a password is set"),
            from_kdbx3: false,
        }
    }
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
    fn unused_attachments_are_dropped_and_references_renumbered() {
        let attachment = |r: &str| format!("<Binary><Key>{r}</Key><Value Ref=\"{r}\"/></Binary>");
        let mut database = Database::from_document(document(&format!(
            "{}<History><Entry>{}{}</Entry></History>",
            attachment("2"),
            attachment("2"),
            attachment("9")
        )));
        database.inner.binaries = (0..4u8)
            .map(|i| Binary {
                protected: false,
                data: Zeroizing::new(vec![i]),
            })
            .collect();

        database.drop_unused_binaries();

        let data: Vec<u8> = database.binaries().iter().map(|b| b.data[0]).collect();
        assert_eq!(data, [2]);
        let mut references = Vec::new();
        for_each_binary_ref(&mut database.document, &mut |r| references.push(r.clone()));
        assert_eq!(references, ["0", "0", "9"]);
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
