use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use zeroize::{Zeroize, Zeroizing};

use super::error::{KdbxError, Result};
use super::inner_header::ProtectedStream;

const MAX_DEPTH: usize = 128;
const MAX_ELEMENTS: usize = 5_000_000;

/// Lossless XML element. Every element, attribute and text node of the
/// database is kept, including ones SailVault does not interpret, so a
/// writer can emit them unchanged. Protected values hold their plaintext and
/// keep the `Protected` attribute.
#[derive(Clone, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Node>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(Zeroizing<String>),
}

impl Element {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|child| match child {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|element| element.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |element| element.name == name)
    }

    /// Concatenated text of the element. Empty for elements without text.
    pub fn text(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::new());
        for child in &self.children {
            if let Node::Text(part) = child {
                text.push_str(part);
            }
        }
        text
    }

    pub fn is_protected(&self) -> bool {
        self.attribute("Protected") == Some("True")
    }
}

impl fmt::Debug for Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Element")
            .field("name", &self.name)
            .field("children", &self.elements().count())
            .finish()
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Element(element) => element.fmt(f),
            Self::Text(_) => f.write_str("Text(..)"),
        }
    }
}

/// Parses the database XML into its root element and decrypts protected
/// values with the inner stream in document order.
pub(crate) fn parse(xml: &[u8], stream: &mut ProtectedStream) -> Result<Element> {
    let mut reader = Reader::from_reader(xml);
    let mut stack: Vec<Element> = Vec::new();
    let mut root = None;
    let mut element_count = 0usize;

    loop {
        let event = reader
            .read_event()
            .map_err(|_| KdbxError::InvalidXml("malformed document"))?;
        match event {
            Event::Start(_) | Event::Empty(_) if root.is_some() => {
                return Err(KdbxError::InvalidXml("content after the root element"));
            }
            Event::Start(start) => {
                element_count += 1;
                if stack.len() == MAX_DEPTH {
                    return Err(KdbxError::LimitExceeded("XML nesting depth"));
                }
                if element_count > MAX_ELEMENTS {
                    return Err(KdbxError::LimitExceeded("XML elements"));
                }
                stack.push(element(&start)?);
            }
            Event::Empty(start) => {
                element_count += 1;
                if element_count > MAX_ELEMENTS {
                    return Err(KdbxError::LimitExceeded("XML elements"));
                }
                let empty = element(&start)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(empty)),
                    None => root = Some(empty),
                }
            }
            Event::End(_) => {
                let mut finished = stack
                    .pop()
                    .ok_or(KdbxError::InvalidXml("unbalanced end tag"))?;
                finish(&mut finished, stream)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(finished)),
                    None => root = Some(finished),
                }
            }
            Event::Text(text) => {
                let text = text
                    .xml10_content()
                    .map_err(|_| KdbxError::InvalidXml("text encoding"))?;
                push_text(&mut stack, &text)?;
            }
            Event::CData(data) => {
                let data = data
                    .decode()
                    .map_err(|_| KdbxError::InvalidXml("CDATA encoding"))?;
                push_text(&mut stack, &data)?;
            }
            Event::GeneralRef(reference) => {
                let character = match reference
                    .resolve_char_ref()
                    .map_err(|_| KdbxError::InvalidXml("character reference"))?
                {
                    Some(character) => character,
                    None => predefined_entity(&reference)?,
                };
                push_text(&mut stack, character.encode_utf8(&mut [0u8; 4]))?;
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }

    if !stack.is_empty() {
        return Err(KdbxError::InvalidXml("unclosed element"));
    }
    root.ok_or(KdbxError::InvalidXml("missing root element"))
}

fn element(start: &BytesStart<'_>) -> Result<Element> {
    let name = std::str::from_utf8(start.name().as_ref())
        .map_err(|_| KdbxError::InvalidXml("element name"))?
        .to_owned();
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| KdbxError::InvalidXml("attribute"))?;
        let key = std::str::from_utf8(attribute.key.as_ref())
            .map_err(|_| KdbxError::InvalidXml("attribute name"))?
            .to_owned();
        let value = attribute
            .unescape_value()
            .map_err(|_| KdbxError::InvalidXml("attribute value"))?
            .into_owned();
        attributes.push((key, value));
    }
    Ok(Element {
        name,
        attributes,
        children: Vec::new(),
    })
}

fn push_text(stack: &mut [Element], text: &str) -> Result<()> {
    let Some(parent) = stack.last_mut() else {
        return if text.trim().is_empty() {
            Ok(())
        } else {
            Err(KdbxError::InvalidXml("text outside the root element"))
        };
    };
    match parent.children.last_mut() {
        Some(Node::Text(existing)) => existing.push_str(text),
        _ => parent
            .children
            .push(Node::Text(Zeroizing::new(text.to_owned()))),
    }
    Ok(())
}

/// Drops indentation between child elements and decrypts protected values.
fn finish(element: &mut Element, stream: &mut ProtectedStream) -> Result<()> {
    if element.elements().next().is_some() {
        element
            .children
            .retain(|child| !matches!(child, Node::Text(text) if text.trim().is_empty()));
    }
    if element.is_protected() {
        let ciphertext = element.text();
        let mut plaintext = Zeroizing::new(
            STANDARD
                .decode(ciphertext.trim())
                .map_err(|_| KdbxError::InvalidXml("protected value"))?,
        );
        stream.apply(&mut plaintext);
        let plaintext = String::from_utf8(std::mem::take(&mut *plaintext)).map_err(|error| {
            error.into_bytes().zeroize();
            KdbxError::InvalidXml("protected value encoding")
        })?;
        element.children.clear();
        if !plaintext.is_empty() {
            element.children.push(Node::Text(Zeroizing::new(plaintext)));
        }
    }
    Ok(())
}

fn predefined_entity(reference: &[u8]) -> Result<char> {
    match reference {
        b"lt" => Ok('<'),
        b"gt" => Ok('>'),
        b"amp" => Ok('&'),
        b"quot" => Ok('"'),
        b"apos" => Ok('\''),
        _ => Err(KdbxError::InvalidXml("unknown entity")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> ProtectedStream {
        ProtectedStream::new(&[0u8; 64])
    }

    #[test]
    fn keeps_unknown_elements_attributes_and_text() {
        let xml = "<?xml version=\"1.0\"?>\n<KeePassFile>\n\t<Meta>\n\t\t<FutureField Mode=\"x &amp; y\">\
                   kept</FutureField>\n\t</Meta>\n\t<Notes>  leading and trailing  \n</Notes>\
                   <Mixed>a &lt;b&gt; &#x1F510; <![CDATA[<raw>]]></Mixed><Empty/></KeePassFile>";
        let root = parse(xml.as_bytes(), &mut stream()).unwrap();

        let future = root.child("Meta").unwrap().child("FutureField").unwrap();
        assert_eq!(future.attribute("Mode"), Some("x & y"));
        assert_eq!(*future.text(), "kept");
        assert_eq!(
            *root.child("Notes").unwrap().text(),
            "  leading and trailing  \n"
        );
        assert_eq!(*root.child("Mixed").unwrap().text(), "a <b> 🔐 <raw>");
        assert!(root.child("Empty").unwrap().children.is_empty());
        let names: Vec<&str> = root.elements().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Meta", "Notes", "Mixed", "Empty"]);
    }

    #[test]
    fn decrypts_protected_values_in_document_order() {
        let mut keystream = stream();
        let encrypt = |plaintext: &str, keystream: &mut ProtectedStream| {
            let mut bytes = plaintext.as_bytes().to_vec();
            keystream.apply(&mut bytes);
            STANDARD.encode(bytes)
        };
        let first = encrypt("first secret", &mut keystream);
        let second = encrypt("second secret", &mut keystream);
        let xml = format!(
            "<KeePassFile><Value Protected=\"True\">{first}</Value><Value>plain</Value>\
             <Value Protected=\"True\"/><Value Protected=\"True\">{second}</Value></KeePassFile>"
        );
        let root = parse(xml.as_bytes(), &mut stream()).unwrap();
        let values: Vec<String> = root.elements().map(|e| e.text().to_string()).collect();
        assert_eq!(values, ["first secret", "plain", "", "second secret"]);
        assert!(root.elements().next().unwrap().is_protected());
    }

    #[test]
    fn rejects_malformed_and_oversized_documents() {
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        for xml in [
            "<KeePassFile><Open></KeePassFile>",
            "<KeePassFile>&unknown;</KeePassFile>",
            "<KeePassFile/><Second/>",
            "text only",
            deep.as_str(),
        ] {
            assert!(parse(xml.as_bytes(), &mut stream()).is_err(), "{xml}");
        }
    }
}
