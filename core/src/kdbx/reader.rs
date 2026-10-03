use super::error::{KdbxError, Result};

/// Bounds-checked little-endian reader over untrusted bytes.
pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.position == self.data.len()
    }

    pub(crate) fn take(&mut self, length: usize, error: KdbxError) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .filter(|&end| end <= self.data.len())
            .ok_or(error)?;
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    pub(crate) fn array<const N: usize>(&mut self, error: KdbxError) -> Result<[u8; N]> {
        let mut array = [0u8; N];
        array.copy_from_slice(self.take(N, error)?);
        Ok(array)
    }

    pub(crate) fn u8(&mut self, error: KdbxError) -> Result<u8> {
        Ok(self.array::<1>(error)?[0])
    }

    pub(crate) fn u16(&mut self, error: KdbxError) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array(error)?))
    }

    pub(crate) fn u32(&mut self, error: KdbxError) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array(error)?))
    }

    pub(crate) fn i32(&mut self, error: KdbxError) -> Result<i32> {
        Ok(i32::from_le_bytes(self.array(error)?))
    }
}
