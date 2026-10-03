use super::error::{KdbxError, Result};
use super::reader::ByteReader;

const VERSION: u16 = 0x0100;
const CRITICAL_MASK: u16 = 0xFF00;
const MAX_ENTRIES: usize = 64;

const TYPE_END: u8 = 0x00;
const TYPE_UINT32: u8 = 0x04;
const TYPE_UINT64: u8 = 0x05;
const TYPE_BOOL: u8 = 0x08;
const TYPE_INT32: u8 = 0x0C;
const TYPE_INT64: u8 = 0x0D;
const TYPE_STRING: u8 = 0x18;
const TYPE_BYTE_ARRAY: u8 = 0x42;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

/// KDBX 4 VariantDictionary (KDF parameters, public custom data). Entries
/// keep their order so the dictionary can be written back unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariantDictionary {
    entries: Vec<(String, Value)>,
}

impl VariantDictionary {
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        let invalid = KdbxError::InvalidHeader("variant dictionary");
        let mut reader = ByteReader::new(data);
        if reader.u16(invalid)? & CRITICAL_MASK > VERSION & CRITICAL_MASK {
            return Err(KdbxError::InvalidHeader("variant dictionary version"));
        }

        let mut entries = Vec::new();
        loop {
            let value_type = reader.u8(invalid)?;
            if value_type == TYPE_END {
                break;
            }
            if entries.len() == MAX_ENTRIES {
                return Err(KdbxError::LimitExceeded("variant dictionary entries"));
            }
            let name = read_sized(&mut reader, invalid)?;
            let name = String::from_utf8(name.to_vec()).map_err(|_| invalid)?;
            let value = read_sized(&mut reader, invalid)?;
            entries.push((name, decode_value(value_type, value).ok_or(invalid)?));
        }
        // Bytes after the end marker are ignored, as in KeePassXC.
        Ok(Self { entries })
    }

    pub(crate) fn from_entries(entries: Vec<(String, Value)>) -> Self {
        Self { entries }
    }

    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = VERSION.to_le_bytes().to_vec();
        for (name, value) in &self.entries {
            out.push(type_id(value));
            write_sized(&mut out, name.as_bytes())?;
            match value {
                Value::UInt32(v) => write_sized(&mut out, &v.to_le_bytes())?,
                Value::UInt64(v) => write_sized(&mut out, &v.to_le_bytes())?,
                Value::Bool(v) => write_sized(&mut out, &[u8::from(*v)])?,
                Value::Int32(v) => write_sized(&mut out, &v.to_le_bytes())?,
                Value::Int64(v) => write_sized(&mut out, &v.to_le_bytes())?,
                Value::String(v) => write_sized(&mut out, v.as_bytes())?,
                Value::ByteArray(v) => write_sized(&mut out, v)?,
            }
        }
        out.push(TYPE_END);
        Ok(out)
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }

    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }
}

fn read_sized<'a>(reader: &mut ByteReader<'a>, invalid: KdbxError) -> Result<&'a [u8]> {
    let length = usize::try_from(reader.i32(invalid)?).map_err(|_| invalid)?;
    reader.take(length, invalid)
}

fn write_sized(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = i32::try_from(bytes.len())
        .map_err(|_| KdbxError::LimitExceeded("variant dictionary value"))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn type_id(value: &Value) -> u8 {
    match value {
        Value::UInt32(_) => TYPE_UINT32,
        Value::UInt64(_) => TYPE_UINT64,
        Value::Bool(_) => TYPE_BOOL,
        Value::Int32(_) => TYPE_INT32,
        Value::Int64(_) => TYPE_INT64,
        Value::String(_) => TYPE_STRING,
        Value::ByteArray(_) => TYPE_BYTE_ARRAY,
    }
}

fn decode_value(value_type: u8, bytes: &[u8]) -> Option<Value> {
    Some(match value_type {
        TYPE_UINT32 => Value::UInt32(u32::from_le_bytes(bytes.try_into().ok()?)),
        TYPE_UINT64 => Value::UInt64(u64::from_le_bytes(bytes.try_into().ok()?)),
        TYPE_BOOL => match bytes {
            [value] => Value::Bool(*value != 0),
            _ => return None,
        },
        TYPE_INT32 => Value::Int32(i32::from_le_bytes(bytes.try_into().ok()?)),
        TYPE_INT64 => Value::Int64(i64::from_le_bytes(bytes.try_into().ok()?)),
        TYPE_STRING => Value::String(String::from_utf8(bytes.to_vec()).ok()?),
        TYPE_BYTE_ARRAY => Value::ByteArray(bytes.to_vec()),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value_type: u8, name: &str, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![value_type];
        bytes.extend_from_slice(&(name.len() as i32).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&(value.len() as i32).to_le_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    #[test]
    fn parses_all_value_types_in_order() {
        let mut data = VERSION.to_le_bytes().to_vec();
        data.extend(entry(TYPE_UINT32, "a", &7u32.to_le_bytes()));
        data.extend(entry(TYPE_UINT64, "b", &8u64.to_le_bytes()));
        data.extend(entry(TYPE_BOOL, "c", &[1]));
        data.extend(entry(TYPE_INT32, "d", &(-9i32).to_le_bytes()));
        data.extend(entry(TYPE_INT64, "e", &(-10i64).to_le_bytes()));
        data.extend(entry(TYPE_STRING, "f", b"text"));
        data.extend(entry(TYPE_BYTE_ARRAY, "g", &[1, 2, 3]));
        data.push(TYPE_END);

        let dictionary = VariantDictionary::parse(&data).unwrap();
        let names: Vec<&str> = dictionary
            .entries()
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names, ["a", "b", "c", "d", "e", "f", "g"]);
        assert_eq!(dictionary.get("b"), Some(&Value::UInt64(8)));
        assert_eq!(dictionary.get("f"), Some(&Value::String("text".into())));
        assert_eq!(dictionary.serialize().unwrap(), data);
    }

    #[test]
    fn rejects_malformed_input() {
        let newer = 0x0200u16.to_le_bytes().to_vec();
        let mut truncated = VERSION.to_le_bytes().to_vec();
        truncated.extend(&entry(TYPE_UINT32, "a", &7u32.to_le_bytes())[..6]);
        let mut wrong_size = VERSION.to_le_bytes().to_vec();
        wrong_size.extend(entry(TYPE_UINT64, "a", &7u32.to_le_bytes()));
        wrong_size.push(TYPE_END);
        for data in [newer, truncated, wrong_size] {
            assert!(VariantDictionary::parse(&data).is_err());
        }
    }
}
