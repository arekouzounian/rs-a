//! # Error Handling
//! This crate will define various errors that are generated throughout the process of
//! key generation, encryption, decryption, serialization, and more.

use core::fmt::{self, Display};
use std::error;

#[derive(Debug)]
pub enum RsaErrorKind {
    OptionsError,
    SerialError,
    CryptographyError,
    MaskGenerationFunctionError,
}

#[derive(Debug)]
pub struct RsaError {
    kind: RsaErrorKind,
    message: String,
}

impl Display for RsaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err_kind = match self.kind {
            RsaErrorKind::OptionsError => "OptionsError",
            RsaErrorKind::SerialError => "SerialError",
            RsaErrorKind::CryptographyError => "CryptographyError",
            RsaErrorKind::MaskGenerationFunctionError => "MaskGenerationFunctionError",
        };

        write!(f, "{}: {}", err_kind, self.message)
    }
}

impl error::Error for RsaError {}

impl RsaError {
    pub fn new(kind: RsaErrorKind, message: String) -> Self {
        Self { kind, message }
    }
}
