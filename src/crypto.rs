//! This file will handle the actual encryption process
//! Encryption, Decryption, and signing

use num::BigUint;

use crate::{
    errors::RsaCryptographyError,
    keygen::{RsaPrivateKey, RsaPublicKey},
};

pub trait RsaKey {
    fn crypt(&self, message: &BigUint) -> Result<BigUint, RsaCryptographyError>;
}

impl RsaKey for RsaPublicKey {
    fn crypt(&self, message: &BigUint) -> Result<BigUint, RsaCryptographyError> {
        if message >= &self.modulus {
            return Err(RsaCryptographyError::with_str(
                "message representative out of range",
            ));
        }

        Ok(message.modpow(&self.public_exponent, &self.modulus))
    }
}

impl RsaKey for RsaPrivateKey {
    fn crypt(&self, ciphertext: &BigUint) -> Result<BigUint, RsaCryptographyError> {
        if ciphertext >= &self.modulus {
            return Err(RsaCryptographyError::with_str(
                "ciphertext representative out of range",
            ));
        }

        let m_1 = ciphertext.modpow(&self.exponent1, &self.prime1);
        let m_2 = ciphertext.modpow(&self.exponent2, &self.prime2);

        let h = ((&m_1 - &m_2) * &self.coefficient) % &self.prime1;

        Ok(m_2 + &self.prime2 * h)
    }
}
