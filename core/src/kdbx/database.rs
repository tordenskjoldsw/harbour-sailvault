use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use super::error::{KdbxError, Result};
use super::header::OuterHeader;
use super::inner_header::{Binary, InnerHeader};
use super::key::CompositeKey;
use super::payload::{self, PayloadKeys};
use super::xml::{self, Element};

const UUID_LENGTH: usize = 16;

/// An unlocked KDBX 4 database: the outer header, the inner header with the
/// attachment pool, and the complete XML document.
pub struct Database {
    header: OuterHeader,
    inner: InnerHeader,
    document: Element,
}

impl Database {
    /// Unlocks a KDBX 4 file. Runs the KDF, so it must not run on the UI
    /// thread.
    pub fn open(data: &[u8], key: &CompositeKey) -> Result<Self> {
        let (header, header_length) = OuterHeader::parse(data)?;
        let transformed = header.kdf.transform(key)?;
        let keys = PayloadKeys::derive(&header, &transformed);
        let payload_start = payload::verify_header(data, &header, header_length, &keys)?;
        let plaintext = payload::decrypt(&data[payload_start..], &header, &keys)?;

        let (mut inner, xml_start) = InnerHeader::parse(&plaintext)?;
        let document = xml::parse(&plaintext[xml_start..], &mut inner.stream)?;
        if document.name != "KeePassFile" {
            return Err(KdbxError::InvalidXml("unexpected root element"));
        }
        let database = Self {
            header,
            inner,
            document,
        };
        database.root_group()?;
        Ok(database)
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
            .is_some_and(|enabled| *enabled.text() == "False")
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

    pub fn fields(&self) -> impl Iterator<Item = Field<'a>> {
        self.0.children_named("String").filter_map(|string| {
            Some(Field {
                key: string.child("Key")?,
                value: string.child("Value")?,
            })
        })
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

fn decode_uuid(element: &Element) -> Option<[u8; UUID_LENGTH]> {
    STANDARD.decode(element.text().trim()).ok()?.try_into().ok()
}
