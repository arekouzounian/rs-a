//! This file will handle the actual encryption process
//! Encryption, Decryption, and signing

use num::BigUint;

pub trait RsaKey {
    fn encrypt(&self, message: BigUint) -> BigUint;
    fn decrypt(&self, message: BigUint) -> BigUint;
}
