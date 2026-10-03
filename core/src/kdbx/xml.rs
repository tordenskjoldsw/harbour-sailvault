use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use zeroize::{Zeroize, Zeroizing};

use super::error::{KdbxError, Result};
use super::inner_header::ProtectedStream;
use crate::secret::{self, ByteSink, SecretBuffer};

const MAX_DEPTH: usize = 128;
const MAX_ELEMENTS: usize = 5_000_000;
// KeePass XML uses at most a few attributes per element.
const MAX_ATTRIBUTES: usize = 64;
const DECLARATION: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";

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

    pub fn child_mut(&mut self, name: &str) -> Option<&mut Element> {
        self.children.iter_mut().find_map(|child| match child {
            Node::Element(element) if element.name == name => Some(element),
            _ => None,
        })
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |element| element.name == name)
    }

    /// Concatenated text of the element. Empty for elements without text.
    pub fn text(&self) -> Zeroizing<String> {
        let length = self
            .children
            .iter()
            .map(|child| match child {
                Node::Text(part) => part.len(),
                Node::Element(_) => 0,
            })
            .sum();
        let mut text = Zeroizing::new(String::with_capacity(length));
        for child in &self.children {
            if let Node::Text(part) = child {
                text.push_str(part);
            }
        }
        text
    }

    pub fn is_protected(&self) -> bool {
        self.attribute("Protected").and_then(parse_bool) == Some(true)
    }
}

/// Boolean as KeePassXC reads it: `True`/`False` in any case, or `1`/`0`.
/// Anything else, such as `null`, is `None`.
pub fn parse_bool(text: &str) -> Option<bool> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("true") || text == "1" {
        Some(true)
    } else if text.eq_ignore_ascii_case("false") || text == "0" {
        Some(false)
    } else {
        None
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
    // The duplicate-name check is quadratic in the attribute count
    // (RUSTSEC-2026-0194); the fixed quick-xml needs a newer Rust than the
    // SDK target has, so the check is off and the count is capped instead.
    let mut parsed = start.attributes();
    parsed.with_checks(false);
    for attribute in parsed {
        if attributes.len() == MAX_ATTRIBUTES {
            return Err(KdbxError::LimitExceeded("XML attributes"));
        }
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

/// Drops characters the writer cannot represent, so a saved file reads back
/// as the same document. Protected values arrive here as base64 and are
/// decrypted later, so their plaintext is kept exactly.
fn push_text(stack: &mut [Element], text: &str) -> Result<()> {
    let filtered;
    let text = if text.chars().all(is_xml10_char) {
        text
    } else {
        filtered = Zeroizing::new(
            text.chars()
                .filter(|&c| is_xml10_char(c))
                .collect::<String>(),
        );
        filtered.as_str()
    };
    let Some(parent) = stack.last_mut() else {
        return if text.trim().is_empty() {
            Ok(())
        } else {
            Err(KdbxError::InvalidXml("text outside the root element"))
        };
    };
    match parent.children.last_mut() {
        Some(Node::Text(existing)) => secret::push_str(existing, text),
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

/// Serializes the document as KeePassXC does: tab indentation, empty
/// elements self-closed, protected values encrypted with the inner stream in
/// document order and base64 encoded.
pub(crate) fn write(root: &Element, stream: &mut ProtectedStream, out: &mut SecretBuffer) {
    out.extend_from_slice(DECLARATION);
    write_element(root, Some(0), stream, out);
    out.push(b'\n');
}

/// `depth` is `None` inside mixed content, where added whitespace would
/// change the text.
fn write_element(
    element: &Element,
    depth: Option<usize>,
    stream: &mut ProtectedStream,
    out: &mut SecretBuffer,
) {
    if let Some(depth) = depth {
        indent(depth, out);
    }
    out.push(b'<');
    out.extend_from_slice(element.name.as_bytes());
    for (key, value) in &element.attributes {
        out.push(b' ');
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(b"=\"");
        escape(value, true, out);
        out.push(b'"');
    }

    if element.is_protected() {
        let plaintext = element.text();
        if plaintext.is_empty() {
            out.extend_from_slice(b"/>");
            return;
        }
        let mut ciphertext = Zeroizing::new(plaintext.as_bytes().to_vec());
        stream.apply(&mut ciphertext);
        out.push(b'>');
        out.extend_from_slice(STANDARD.encode(ciphertext.as_slice()).as_bytes());
    } else if element.children.is_empty() {
        out.extend_from_slice(b"/>");
        return;
    } else {
        out.push(b'>');
        let only_elements = element
            .children
            .iter()
            .all(|child| matches!(child, Node::Element(_)));
        let child_depth = depth.filter(|_| only_elements).map(|depth| depth + 1);
        for child in &element.children {
            match child {
                Node::Element(child) => write_element(child, child_depth, stream, out),
                Node::Text(text) => escape(text, false, out),
            }
        }
        if let Some(depth) = child_depth {
            indent(depth - 1, out);
        }
    }
    out.extend_from_slice(b"</");
    out.extend_from_slice(element.name.as_bytes());
    out.push(b'>');
}

fn indent(depth: usize, out: &mut SecretBuffer) {
    out.push(b'\n');
    for _ in 0..depth {
        out.push(b'\t');
    }
}

/// False for the characters XML 1.0 forbids or discourages, the set
/// KeePassXC strips (`KdbxXmlWriter::stripInvalidXml10Chars`).
pub(crate) fn is_xml10_char(character: char) -> bool {
    !matches!(
        character,
        '\0'..='\x08'
            | '\x0B'
            | '\x0C'
            | '\x0E'..='\x1F'
            | '\x7F'..='\u{84}'
            | '\u{86}'..='\u{9F}'
            | '\u{FFFE}'
            | '\u{FFFF}'
    )
}

/// Escapes markup and drops the characters XML 1.0 forbids. A carriage
/// return becomes a character reference, because a parser turns a literal
/// one into a line feed.
fn escape(text: &str, attribute: bool, out: &mut SecretBuffer) {
    for character in text.chars() {
        match character {
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '&' => out.extend_from_slice(b"&amp;"),
            '"' if attribute => out.extend_from_slice(b"&quot;"),
            '\r' => out.extend_from_slice(b"&#13;"),
            character if !is_xml10_char(character) => {}
            character => out.extend_from_slice(character.encode_utf8(&mut [0u8; 4]).as_bytes()),
        }
    }
}

pub(crate) fn predefined_entity(reference: &[u8]) -> Result<char> {
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
    fn reads_booleans_like_keepassxc() {
        for (text, expected) in [
            ("True", Some(true)),
            ("true", Some(true)),
            ("1", Some(true)),
            ("False", Some(false)),
            ("FALSE", Some(false)),
            ("0", Some(false)),
            ("null", None),
            ("yes", None),
        ] {
            assert_eq!(parse_bool(text), expected, "{text}");
        }
    }

    #[test]
    fn caps_attributes_per_element() {
        let attributes: String = (0..=MAX_ATTRIBUTES)
            .map(|i| format!(" a{i}=\"x\""))
            .collect();
        let xml = format!("<KeePassFile{attributes}/>");
        assert_eq!(
            parse(xml.as_bytes(), &mut stream()).map(|_| ()),
            Err(KdbxError::LimitExceeded("XML attributes"))
        );
    }

    fn written(root: &Element) -> Vec<u8> {
        let mut out = SecretBuffer::default();
        write(root, &mut stream(), &mut out);
        out.to_vec()
    }

    #[test]
    fn writes_keepassxc_formatting_and_encrypts_protected_values() {
        let mut encrypted = b"secret".to_vec();
        stream().apply(&mut encrypted);
        let encrypted = STANDARD.encode(encrypted);
        let xml = format!(
            "<KeePassFile><Meta><Generator>a &amp; b</Generator><Color/></Meta><Root>\
             <Group><Entry><String><Key>Password</Key><Value Protected=\"True\">{encrypted}\
             </Value></String><String><Key>Notes</Key><Value Protected=\"True\"/></String>\
             </Entry></Group></Root></KeePassFile>"
        );
        let parsed = parse(xml.as_bytes(), &mut stream()).unwrap();
        assert_eq!(
            *parsed
                .child("Root")
                .unwrap()
                .child("Group")
                .unwrap()
                .child("Entry")
                .unwrap()
                .child("String")
                .unwrap()
                .child("Value")
                .unwrap()
                .text(),
            "secret"
        );
        let out = String::from_utf8(written(&parsed)).unwrap();

        let expected = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<KeePassFile>\n\
             \t<Meta>\n\t\t<Generator>a &amp; b</Generator>\n\t\t<Color/>\n\t</Meta>\n\t<Root>\n\
             \t\t<Group>\n\t\t\t<Entry>\n\t\t\t\t<String>\n\t\t\t\t\t<Key>Password</Key>\n\
             \t\t\t\t\t<Value Protected=\"True\">{}</Value>\n\t\t\t\t</String>\n\t\t\t\t<String>\n\
             \t\t\t\t\t<Key>Notes</Key>\n\t\t\t\t\t<Value Protected=\"True\"/>\n\t\t\t\t</String>\n\
             \t\t\t</Entry>\n\t\t</Group>\n\t</Root>\n</KeePassFile>\n",
            encrypted
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn written_document_parses_back_identically() {
        let xml = "<?xml version=\"1.0\"?><KeePassFile><Meta><FutureField Mode=\"x &amp; y &quot;q&quot;\">\
                   kept</FutureField></Meta><Notes>  leading and trailing  \n</Notes>\
                   <Mixed>a &lt;b&gt; <Inner>i</Inner> tail</Mixed><Empty/>\
                   <Value Protected=\"True\">PK0nXQ==</Value></KeePassFile>";
        let original = parse(xml.as_bytes(), &mut stream()).unwrap();
        let reparsed = parse(&written(&original), &mut stream()).unwrap();
        assert!(reparsed == original);
        assert!(parse(&written(&reparsed), &mut stream()).unwrap() == original);
    }

    #[test]
    fn strips_characters_xml_forbids() {
        let root = Element {
            name: "KeePassFile".into(),
            attributes: vec![("a".into(), "x\u{1}y\"".into())],
            children: vec![Node::Text(Zeroizing::new(
                "tab\tnl\nbell\u{7}del\u{7f}ok".into(),
            ))],
        };
        assert_eq!(
            String::from_utf8(written(&root)).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <KeePassFile a=\"xy&quot;\">tab\tnl\nbelldelok</KeePassFile>\n"
        );
    }

    #[test]
    fn carriage_returns_survive_and_forbidden_references_are_dropped() {
        let root = Element {
            name: "KeePassFile".into(),
            attributes: vec![("a".into(), "x\ry".into())],
            children: vec![Node::Text(Zeroizing::new("one\r\ntwo\rthree".into()))],
        };
        let written = written(&root);
        assert!(!written.contains(&b'\r'));
        assert!(parse(&written, &mut stream()).unwrap() == root);

        let parsed = parse(b"<KeePassFile>a&#1;b&#13;c</KeePassFile>", &mut stream()).unwrap();
        assert_eq!(*parsed.text(), "ab\rc");
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
