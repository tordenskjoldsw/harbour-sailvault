use base64::alphabet::STANDARD;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;

use super::error::{CryptoError, Result};

// Bitwarden clients accept standard base64 with or without padding.
const ENGINE: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub(crate) fn decode(value: &str) -> Result<Vec<u8>> {
    ENGINE
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncString)
}
