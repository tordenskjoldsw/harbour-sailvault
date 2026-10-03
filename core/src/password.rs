//! Password generator for new entries. Characters are drawn uniformly from
//! the selected classes by rejection sampling, and every selected class
//! appears at least once, as KeePassXC's generator does by default.

use zeroize::Zeroizing;

use crate::random;

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 128;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterClasses {
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl CharacterClasses {
    fn selected(self) -> Vec<&'static [u8]> {
        [
            (self.lower, LOWER),
            (self.upper, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(selected, _)| *selected)
        .map(|(_, class)| class)
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    InvalidParameters,
    RandomUnavailable,
}

impl From<getrandom::Error> for PasswordError {
    fn from(_: getrandom::Error) -> Self {
        Self::RandomUnavailable
    }
}

pub fn generate(
    length: usize,
    classes: CharacterClasses,
) -> Result<Zeroizing<String>, PasswordError> {
    let selected = classes.selected();
    if selected.is_empty() || !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(PasswordError::InvalidParameters);
    }
    let alphabet: Vec<u8> = selected.concat();
    loop {
        let mut password = Zeroizing::new(Vec::with_capacity(length));
        while password.len() < length {
            if let Some(index) = uniform_index(alphabet.len())? {
                password.push(alphabet[index]);
            }
        }
        if selected
            .iter()
            .all(|class| password.iter().any(|byte| class.contains(byte)))
        {
            let bytes = std::mem::take(&mut *password);
            return Ok(Zeroizing::new(
                String::from_utf8(bytes).expect("the alphabet is ASCII"),
            ));
        }
    }
}

/// One uniformly distributed index below `bound`, or `None` for a draw that
/// falls into the rejected remainder.
fn uniform_index(bound: usize) -> Result<Option<usize>, PasswordError> {
    let bound = u64::try_from(bound).map_err(|_| PasswordError::InvalidParameters)?;
    let draw = u64::from(u32::from_le_bytes(random::array()?));
    let accepted = (u64::from(u32::MAX) + 1) / bound * bound;
    if draw >= accepted {
        return Ok(None);
    }
    Ok(Some(
        usize::try_from(draw % bound).expect("below the usize bound"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: CharacterClasses = CharacterClasses {
        lower: true,
        upper: true,
        digits: true,
        symbols: true,
    };

    #[test]
    fn uses_only_and_all_selected_classes() {
        let digits_and_symbols = CharacterClasses {
            lower: false,
            upper: false,
            digits: true,
            symbols: true,
        };
        for _ in 0..50 {
            let password = generate(12, digits_and_symbols).unwrap();
            assert_eq!(password.len(), 12);
            assert!(password
                .bytes()
                .all(|b| DIGITS.contains(&b) || SYMBOLS.contains(&b)));
            assert!(password.bytes().any(|b| DIGITS.contains(&b)));
            assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn every_character_of_the_alphabet_is_reachable() {
        let alphabet = [LOWER, UPPER, DIGITS, SYMBOLS].concat();
        let mut seen = vec![false; 256];
        for _ in 0..40 {
            for byte in generate(MAX_LENGTH, ALL).unwrap().bytes() {
                seen[usize::from(byte)] = true;
            }
        }
        for byte in alphabet {
            assert!(seen[usize::from(byte)], "{} never drawn", byte as char);
        }
    }

    #[test]
    fn rejects_impossible_requests() {
        let none = CharacterClasses {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
        };
        for (length, classes) in [(20, none), (MIN_LENGTH - 1, ALL), (MAX_LENGTH + 1, ALL)] {
            assert_eq!(
                generate(length, classes).map(|_| ()),
                Err(PasswordError::InvalidParameters)
            );
        }
    }
}
