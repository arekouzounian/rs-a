use core::fmt::{self, Display};
use std::error;

#[derive(Debug)]
pub struct RsaOptionsError {
    message: String,
}

impl Display for RsaOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for RsaOptionsError {}

impl RsaOptionsError {
    pub fn with_str(m: &str) -> Self {
        Self {
            message: String::from(m),
        }
    }

    pub fn new(m: String) -> Self {
        Self { message: m }
    }
}
