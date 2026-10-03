//! Growable buffers for plaintext. A growing `Vec` or `String` frees its old
//! allocation without wiping it; these move the contents into a larger
//! allocation and wipe the old one.

use std::io;
use std::ops::Deref;

use zeroize::Zeroizing;

/// Output that file sections are serialized into.
pub(crate) trait ByteSink {
    fn push(&mut self, byte: u8);
    fn extend_from_slice(&mut self, bytes: &[u8]);
}

impl ByteSink for Vec<u8> {
    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
}

#[derive(Default)]
pub(crate) struct SecretBuffer(Zeroizing<Vec<u8>>);

impl SecretBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Extends the buffer with zeros, or shortens it.
    pub(crate) fn resize(&mut self, length: usize) {
        self.reserve(length.saturating_sub(self.0.len()));
        self.0.resize(length, 0);
    }

    pub(crate) fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    fn reserve(&mut self, additional: usize) {
        let required = self
            .0
            .len()
            .checked_add(additional)
            .expect("buffer length fits in usize");
        if required > self.0.capacity() {
            let mut grown = Vec::with_capacity(required.max(self.0.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.0);
            self.0 = Zeroizing::new(grown);
        }
    }
}

impl ByteSink for SecretBuffer {
    fn push(&mut self, byte: u8) {
        self.reserve(1);
        self.0.push(byte);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.0.extend_from_slice(bytes);
    }
}

impl Deref for SecretBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl io::Write for SecretBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        ByteSink::extend_from_slice(self, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Appends to a string holding secrets, growing it like `SecretBuffer`.
pub(crate) fn push_str(text: &mut Zeroizing<String>, addition: &str) {
    let required = text.len() + addition.len();
    if required > text.capacity() {
        let mut grown = String::with_capacity(required.max(text.capacity().saturating_mul(2)));
        grown.push_str(text);
        *text = Zeroizing::new(grown);
    }
    text.push_str(addition);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_keeps_content() {
        let mut buffer = SecretBuffer::with_capacity(2);
        for byte in 0..100u8 {
            buffer.push(byte);
        }
        buffer.extend_from_slice(&[7; 300]);
        assert_eq!(buffer.len(), 400);
        assert_eq!(buffer[99], 99);
        buffer.resize(500);
        assert_eq!(&buffer[400..], &[0; 100][..]);
        buffer.resize(10);
        assert_eq!(&*buffer.into_inner(), &(0..10u8).collect::<Vec<_>>()[..]);

        let mut text = Zeroizing::new(String::new());
        for _ in 0..50 {
            push_str(&mut text, "abc");
        }
        assert_eq!(text.len(), 150);
        assert!(text.starts_with("abcabc"));
    }
}
