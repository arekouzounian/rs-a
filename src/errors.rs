//! # Error Handling
//! This crate will define various errors that are generated throughout the process of
//! key generation, encryption, decryption, serialization, and more.

use core::fmt::{self, Display};
use std::error;

#[derive(Debug)]
pub enum RsaErrorKind {
    RsaOptionsError,
    RsaSerialError,
    RsaCryptographyError,
}

#[derive(Debug)]
pub struct RsaError {
    kind: RsaErrorKind,
    message: String,
}

impl Display for RsaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err_kind = match self.kind {
            RsaErrorKind::RsaOptionsError => "RsaOptionsError",
            RsaErrorKind::RsaSerialError => "RsaSerialError",
            RsaErrorKind::RsaCryptographyError => "RsaCryptographyError",
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
