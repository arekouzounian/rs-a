//! # Cryptographic Functions
//! This module handles cryptographic primitives, as well as
//! the associated encryption/decryption operations.

use num::BigUint;

use crate::{
    errors::RsaCryptographyError,
    keygen::{RsaPrivateKey, RsaPublicKey},
};

/// This trait is used to implement the RSA Encryption/Decryption primitives.
/// Namely, RSAEP and RSADP. The definitions for these primitives can be found
/// [in Section 5 of RFC8017](https://www.rfc-editor.org/rfc/rfc8017#section-5).
pub trait RsaPrimitive {
    /// Performs a primitive encryption/decryption operation on the input integer.
    /// The integer must be within the range \[0, n-1\] (where n is the RSA modulus),
    /// or else the operation fails, and returns an `RsaCryptographyError`.
    fn crypt(&self, message: &BigUint) -> Result<BigUint, RsaCryptographyError>;
}

impl RsaPrimitive for RsaPublicKey {
    fn crypt(&self, message: &BigUint) -> Result<BigUint, RsaCryptographyError> {
        if message >= &self.modulus {
            return Err(RsaCryptographyError::with_str(
                "message representative out of range",
            ));
        }

        Ok(message.modpow(&self.public_exponent, &self.modulus))
    }
}

impl RsaPrimitive for RsaPrivateKey {
    fn crypt(&self, ciphertext: &BigUint) -> Result<BigUint, RsaCryptographyError> {
        if ciphertext >= &self.modulus {
            return Err(RsaCryptographyError::with_str(
                "ciphertext representative out of range",
            ));
        }

        let m_1 = ciphertext.modpow(&self.exponent1, &self.prime1);
        let m_2 = ciphertext.modpow(&self.exponent2, &self.prime2);

        let h = match m_1 > m_2 {
            true => ((&m_1 - &m_2) * &self.coefficient) % &self.prime1,
            false => ((&m_2 - &m_1) * &self.coefficient) % &self.prime1,
        };

        Ok(m_2 + &self.prime2 * h)
    }
}
