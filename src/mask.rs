//! Utility functions for hashing and mask generation
use crate::errors::RsaError;
use num::integer::div_ceil;
use sha2::{Digest, Sha256};

pub enum HashType {
    Sha2 = 256,
}

/// [MGF1 - RFC8017](https://www.rfc-editor.org/rfc/rfc8017#appendix-B.2)
/// Horribly slow? perhaps.
pub fn mgf(hash_type: HashType, seed: u32, output_len: u32) -> Result<Vec<u8>, RsaError> {
    let hash_len = hash_type as u32;

    if output_len * hash_len > u32::MAX {
        return Err(RsaError::new(
            crate::errors::RsaErrorKind::MaskGenerationFunctionError,
            format!("output_len {} too large!", output_len),
        ));
    }

    let mut t: Vec<u8> = Vec::new();
    // let cast_seed = BigUint::from_u32(seed).unwrap();
    let mut seed = Vec::from(seed.to_le_bytes());

    for i in 0..div_ceil(output_len, hash_len) {
        let last = seed.len() - 1;
        seed.extend(i.to_le_bytes());

        let hash = match hash_type {
            HashType::Sha2 => Sha256::digest(&seed),
        };
        t.extend(hash);

        seed.drain(last..);
    }

    t.drain(output_len as usize - 1..);

    Ok(t)
}
