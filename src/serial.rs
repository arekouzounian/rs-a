//! # Serialization/Deserialization
//! This module is used to provide utilities for serialization and deserialization.
//!
//! More specifically, this module will be used for writing keys to files in
//! various standardized formats, as well as reading keys in from standardized formats.

use crate::keygen::{RsaPrivateKey, RsaPublicKey};
use base64::prelude::*;
use num::traits::ConstZero;
use num::BigUint;
use std::collections::VecDeque;
use std::error::Error;
use std::io::Error as ioError;

/// Reads the entire contents of an OpenSSH public key, and attempts to deserialize into an
/// `RsaPublicKey` object.
pub fn read_openssh_public_key(path: &std::path::Path) -> Result<RsaPublicKey, Box<dyn Error>> {
    let file_contents = std::fs::read_to_string(path)?;

    let b64: &str = file_contents
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ioError::new(std::io::ErrorKind::InvalidInput, "invalid ssh key"))?;

    let decode = BASE64_STANDARD.decode(b64)?;

    let (e, n) = parse_pub_key(&decode)?;
    Ok(RsaPublicKey::new(e, n))
}

/// Returns (exponent, modulus)
fn parse_pub_key(bytes: &Vec<u8>) -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let mut ind: usize = 0;

    let next_four_bytes_as_u32 = |i: &mut usize| {
        let mut x: u32 = 0;

        if *i + 3 >= bytes.len() {
            return None;
        }
        for j in *i..(*i + 3) {
            x += bytes[j] as u32;
            x <<= 8;
        }
        *i += 4;

        Some(x + bytes[*i - 1] as u32)
    };

    let mut len = next_four_bytes_as_u32(&mut ind);

    let mut found_nums: Vec<BigUint> = Vec::with_capacity(3);

    while len.is_some() {
        let l = len.unwrap() as usize;
        if ind + l > bytes.len() {
            break;
        }

        let data = BigUint::from_bytes_le(&bytes[ind..ind + l]);

        found_nums.push(data);

        ind += l;
        len = next_four_bytes_as_u32(&mut ind);
    }

    if found_nums.len() != 3 {
        return Err(Box::new(ioError::new(
            std::io::ErrorKind::InvalidInput,
            "invalid ssh public key format",
        )));
    }

    let m = found_nums.pop().unwrap();
    let e = found_nums.pop().unwrap();

    Ok((e, m))
}

const ASN1_SEQ: u8 = 0x30;
const ASN1_INT: u8 = 0x02;

/*
RSAPublicKey ::= SEQUENCE {
                modulus           INTEGER,  -- n
                publicExponent    INTEGER   -- e
            }
*/
pub fn rsa_public_key_asn1_serialize(key: RsaPublicKey) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    let mod_bytes = encode_asn1_int(&key.modulus);
    let exp_bytes = encode_asn1_int(&key.public_exponent);

    let seq_len = encode_asn1_len(mod_bytes.len() + exp_bytes.len());

    bytes.push(ASN1_SEQ);
    bytes.extend(seq_len);
    bytes.extend(mod_bytes);
    bytes.extend(exp_bytes);

    bytes
}

pub fn rsa_private_key_asn1_serialize(key: RsaPrivateKey) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    let version_bytes = encode_asn1_int(&BigUint::ZERO);
    let mod_bytes = encode_asn1_int(&key.modulus);
    let exp_bytes = encode_asn1_int(&key.public_exponent);
    let d_bytes = encode_asn1_int(&key.private_exponent);
    let p_bytes = encode_asn1_int(&key.prime1);
    let q_bytes = encode_asn1_int(&key.prime2);
    let dp_bytes = encode_asn1_int(&key.exponent1);
    let dq_bytes = encode_asn1_int(&key.exponent2);
    let qinv_bytes = encode_asn1_int(&key.coefficient);

    let seq_len = encode_asn1_len(
        version_bytes.len()
            + mod_bytes.len()
            + exp_bytes.len()
            + d_bytes.len()
            + p_bytes.len()
            + q_bytes.len()
            + dp_bytes.len()
            + dq_bytes.len()
            + qinv_bytes.len(),
    );

    bytes.push(ASN1_SEQ);
    bytes.extend(seq_len);
    bytes.extend(version_bytes);
    bytes.extend(mod_bytes);
    bytes.extend(exp_bytes);
    bytes.extend(d_bytes);
    bytes.extend(p_bytes);
    bytes.extend(q_bytes);
    bytes.extend(dp_bytes);
    bytes.extend(dq_bytes);
    bytes.extend(qinv_bytes);

    bytes
}

fn encode_asn1_len(mut len: usize) -> VecDeque<u8> {
    if len <= 0x7F {
        return VecDeque::from(vec![len as u8]);
    }

    let mut v: VecDeque<u8> = VecDeque::new();

    while len > 0 {
        v.push_front((len & 0xFF) as u8);
        len >>= 8;
    }

    v.push_front(0x80 | v.len() as u8);

    v
}

fn encode_asn1_int(int: &BigUint) -> VecDeque<u8> {
    let mut bytes = VecDeque::from(int.to_bytes_be());

    // If it has a first order bit set, we need to add a 0 byte to the front
    if bytes[0] & 0x80 != 0 {
        bytes.push_front(0x00);
    }

    let len_bytes = encode_asn1_len(bytes.len());
    for b in len_bytes.iter().rev() {
        bytes.push_front(b.clone());
    }
    bytes.push_front(ASN1_INT);

    bytes
}
