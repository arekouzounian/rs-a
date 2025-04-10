//! # Serialization/Deserialization
//! This module is used to provide utilities for serialization and deserialization.
//!
//! More specifically, this module will be used for writing keys to files in
//! various standardized formats, as well as reading keys in from standardized formats.

use crate::errors::{RsaError, RsaErrorKind};
use crate::keygen::{RsaPrivateKey, RsaPublicKey};
use base64::prelude::*;
use num::BigUint;
use std::collections::VecDeque;
use std::error::Error;

// technically DER can have up to 128 bytes for a length
// but for the purposes of this library the largest supported
// number of length bytes is usize/8
const SUPPORTED_DER_LEN_SIZE: usize = (usize::BITS / u8::BITS) as usize;

pub enum AsnDerValues {
    Asn1Seq = 0x30,
    Asn1Int = 0x02,
}

/// Reads the entire contents of an OpenSSH public key, and attempts to deserialize into an
/// `RsaPublicKey` object.
pub fn read_openssh_public_key(path: &std::path::Path) -> Result<RsaPublicKey, Box<dyn Error>> {
    let file_contents = std::fs::read_to_string(path)?;

    let b64: &str = file_contents
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| RsaError::new(RsaErrorKind::SerialError, String::from("invalid ssh key")))?;

    let decode = BASE64_STANDARD.decode(b64)?;

    let (e, n) = parse_pub_key(&decode)?;
    Ok(RsaPublicKey::new(e, n))
}

// https://datatracker.ietf.org/doc/html/rfc7468#section-2
// lines must be 64 characters max
const PEM_LINE_MAX: usize = 64;

pub fn pem_publickey_encode(data: Vec<u8>) -> String {
    let mut ret = String::from("-----BEGIN RSA PUBLIC KEY-----\n");
    let encoded = BASE64_STANDARD.encode(data);
    ret = encoded.chars().enumerate().fold(ret, |mut acc, (i, c)| {
        acc.push(c);
        if (i + 1) % PEM_LINE_MAX == 0 {
            acc.push('\n');
        }
        acc
    });

    ret.push_str("\n-----END RSA PUBLIC KEY-----");
    ret
}

// pretty dirty, doesn't do much checking. Not ideal.
pub fn pem_decode(data: String) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(BASE64_STANDARD.decode(
        data.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>(),
    )?)
}

pub fn pem_privatekey_encode(data: Vec<u8>) -> String {
    let mut ret = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
    let encoded = BASE64_STANDARD.encode(data);
    ret = encoded.chars().enumerate().fold(ret, |mut acc, (i, c)| {
        acc.push(c);
        if (i + 1) % PEM_LINE_MAX == 0 {
            acc.push('\n');
        }
        acc
    });
    ret.push_str("\n-----END RSA PRIVATE KEY-----");
    ret
}

// pub fn pkcs_8_encode()
// pub fn pkcs_8_decode()

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
        return Err(Box::new(RsaError::new(
            RsaErrorKind::SerialError,
            String::from("invalid ssh public key format"),
        )));
    }

    let m = found_nums.pop().unwrap();
    let e = found_nums.pop().unwrap();

    Ok((e, m))
}

/*
RSAPublicKey ::= SEQUENCE {
                modulus           INTEGER,  -- n
                publicExponent    INTEGER   -- e
            }
*/
pub fn rsa_public_key_der_serialize(key: RsaPublicKey) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    let mod_bytes = encode_der_int(&key.modulus);
    let exp_bytes = encode_der_int(&key.public_exponent);

    let seq_len = encode_der_len(mod_bytes.len() + exp_bytes.len());

    bytes.push(AsnDerValues::Asn1Seq as u8);
    bytes.extend(seq_len);
    bytes.extend(mod_bytes);
    bytes.extend(exp_bytes);

    bytes
}

pub fn rsa_private_key_der_serialize(key: RsaPrivateKey) -> Vec<u8> {
    let version_bytes = encode_der_int(&BigUint::ZERO);
    let mod_bytes = encode_der_int(&key.modulus);
    let exp_bytes = encode_der_int(&key.public_exponent);
    let d_bytes = encode_der_int(&key.private_exponent);
    let p_bytes = encode_der_int(&key.prime1);
    let q_bytes = encode_der_int(&key.prime2);
    let dp_bytes = encode_der_int(&key.exponent1);
    let dq_bytes = encode_der_int(&key.exponent2);
    let qinv_bytes = encode_der_int(&key.coefficient);

    let len = version_bytes.len()
        + mod_bytes.len()
        + exp_bytes.len()
        + d_bytes.len()
        + p_bytes.len()
        + q_bytes.len()
        + dp_bytes.len()
        + dq_bytes.len()
        + qinv_bytes.len();

    let mut bytes = Vec::with_capacity(len);

    let seq_len = encode_der_len(len);

    bytes.push(AsnDerValues::Asn1Seq as u8);
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

pub fn rsa_public_key_der_deserialize(data: Vec<u8>) -> Result<RsaPublicKey, RsaError> {
    let mut data: VecDeque<u8> = VecDeque::from(data);
    decode_der_seq(&mut data)?;

    let n = decode_der_int(&mut data)?;
    let e = decode_der_int(&mut data)?;

    Ok(RsaPublicKey::new(e, n))
}

pub fn rsa_private_key_der_deserialize(data: Vec<u8>) -> Result<RsaPrivateKey, RsaError> {
    let mut data: VecDeque<u8> = VecDeque::from(data);
    decode_der_seq(&mut data)?;

    let version = decode_der_int(&mut data)?;
    if version != BigUint::ZERO {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!("Unsupported RSA version: expected 0, actual {}", version),
        ));
    }

    let n = decode_der_int(&mut data)?;
    let e = decode_der_int(&mut data)?;
    let d = decode_der_int(&mut data)?;
    let p = decode_der_int(&mut data)?;
    let q = decode_der_int(&mut data)?;
    let dp = decode_der_int(&mut data)?;
    let dq = decode_der_int(&mut data)?;
    let q_inv = decode_der_int(&mut data)?;

    Ok(RsaPrivateKey::new(0, n, e, d, p, q, dp, dq, q_inv))
}

// add check for unsupported len?
fn encode_der_len(mut len: usize) -> VecDeque<u8> {
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

fn decode_der_len(data: &mut VecDeque<u8>) -> Result<usize, RsaError> {
    if data.len() < 2 {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            String::from("Invalid input length: must have at least 2 bytes"),
        ));
    }

    let lenlen = data.pop_front().unwrap();
    if lenlen <= 0x7F {
        return Ok(lenlen as usize);
    }

    let num_len_bytes = (lenlen & 0x7F) as usize;

    if data.len() < num_len_bytes {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!("Invalid input length: needed 2, have {}", data.len()),
        ));
    } else if num_len_bytes > SUPPORTED_DER_LEN_SIZE {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!(
                "Size not supported: maximum width of a DER object's length is {} bytes",
                SUPPORTED_DER_LEN_SIZE
            ),
        ));
    }

    let mut ret: usize = 0;
    for i in 0..num_len_bytes {
        ret += data.pop_front().unwrap() as usize;

        if i < num_len_bytes - 1 {
            ret <<= 8;
        }
    }

    Ok(ret)
}

fn encode_der_int(int: &BigUint) -> VecDeque<u8> {
    let mut bytes = VecDeque::from(int.to_bytes_be());

    // If it has a first order bit set, we need to add a 0 byte to the front
    if bytes[0] & 0x80 != 0 {
        bytes.push_front(0x00);
    }

    let len_bytes = encode_der_len(bytes.len());
    for b in len_bytes.iter().rev() {
        bytes.push_front(b.clone());
    }
    bytes.push_front(AsnDerValues::Asn1Int as u8);

    bytes
}

fn decode_der_seq(data: &mut VecDeque<u8>) -> Result<(), RsaError> {
    if data.len() < 2 {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!("Invalid input length: needed 2, have {}", data.len()),
        ));
    }

    if data.pop_front().unwrap() != AsnDerValues::Asn1Seq as u8 {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            String::from("Invalid input: doesn't contain SEQ byte"),
        ));
    }

    let len = decode_der_len(data)?;

    if data.len() < len {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!(
                "Invalid input: sequence length {}, actual {}",
                len,
                data.len()
            ),
        ));
    }

    Ok(())
}

fn decode_der_int(data: &mut VecDeque<u8>) -> Result<BigUint, RsaError> {
    if data.len() < 2 {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!("Invalid int width: needed 2, has {}", data.len()),
        ));
    }

    let first = data.pop_front().unwrap();
    if first != AsnDerValues::Asn1Int as u8 {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!(
                "Invalid integer DER tag: tag {}, actual {}",
                AsnDerValues::Asn1Int as u8,
                first,
            ),
        ));
    }

    let mut len = decode_der_len(data)?;

    if data.len() < len {
        return Err(RsaError::new(
            RsaErrorKind::SerialError,
            format!("Invalid input: length {}, actual {}", len, data.len()),
        ));
    }

    let mut bytes = Vec::with_capacity(len);

    let first = data.pop_front().unwrap();
    if first != 0x00 {
        bytes.push(first);
    }
    len -= 1;

    for _ in 0..len {
        bytes.push(data.pop_front().unwrap());
    }

    Ok(BigUint::from_bytes_be(&bytes))
}
