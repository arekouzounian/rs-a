//! # Cryptographic Functions
//! This module handles cryptographic primitives, as well as
//! the associated encryption/decryption operations.

use num::BigInt;
use num_bigint::Sign;

use crate::{
    errors::{RsaError, RsaErrorKind},
    keygen::{RsaPrivateKey, RsaPublicKey},
};

/// This trait is used to implement the RSA Encryption/Decryption primitives.
/// Namely, RSAEP and RSADP. The definitions for these primitives can be found
/// [in Section 5 of RFC8017](https://www.rfc-editor.org/rfc/rfc8017#section-5).
pub trait RsaPrimitive {
    /// Performs a primitive encryption/decryption operation on the input integer.
    /// The integer must be within the range \[0, n-1\] (where n is the RSA modulus),
    /// or else the operation fails, and returns an `RsaCryptographyError`.
    fn crypt(&self, message: &BigInt) -> Result<BigInt, RsaError>;

    fn crypt_with_bytes(&self, message: &[u8]) -> Result<Vec<u8>, RsaError>;
}

pub trait RsaOaepEncrypt {
    fn encrypt(
        &self,
        message: impl AsRef<[u8]>,
        label: Option<impl AsRef<[u8]>>,
    ) -> Result<Vec<u8>, RsaError>;
}

impl RsaPrimitive for RsaPublicKey {
    fn crypt(&self, message: &BigInt) -> Result<BigInt, RsaError> {
        if message >= &self.modulus {
            return Err(RsaError::new(
                RsaErrorKind::CryptographyError,
                String::from("message representative out of range"),
            ));
        }

        Ok(message.modpow(&self.public_exponent, &self.modulus))
    }

    fn crypt_with_bytes(&self, message: &[u8]) -> Result<Vec<u8>, RsaError> {
        let res = self.crypt(&BigInt::from_bytes_le(Sign::Plus, &message))?;
        Ok(res.to_bytes_le().1)
    }
}

impl RsaPrimitive for RsaPrivateKey {
    fn crypt(&self, ciphertext: &BigInt) -> Result<BigInt, RsaError> {
        if ciphertext >= &self.modulus {
            return Err(RsaError::new(
                RsaErrorKind::CryptographyError,
                String::from("ciphertext representative out of range"),
            ));
        }

        let m_1 = ciphertext.modpow(&self.exponent1, &self.prime1);
        let m_2 = ciphertext.modpow(&self.exponent2, &self.prime2);

        let h = ((&m_1 - &m_2) * &self.coefficient) % &self.prime1;

        Ok(m_2 + &self.prime2 * h)
    }

    fn crypt_with_bytes(&self, message: &[u8]) -> Result<Vec<u8>, RsaError> {
        let res = self.crypt(&BigInt::from_bytes_le(Sign::Plus, &message))?;
        Ok(res.to_bytes_le().1)
    }
}
