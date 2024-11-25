//! # Serialization/Deserialization
//! This module is used to provide utilities for serialization and deserialization.
//!
//! More specifically, this module will be used for writing keys to files in
//! various standardized formats, as well as reading keys in from standardized formats.

use crate::keygen::RsaPublicKey;
use base64::prelude::*;
use num::traits::ConstZero;
use num::BigUint;
use std::error::Error;
use std::io::Error as ioError;

const AUTH_MAGIC_STR: &str = "openssh-key-v1\0";

/// Reads the entire contents of an ssh public key, an attempts to deserialize into an
/// `RsaPublicKey` object.
pub fn read_ssh_public_key(path: &std::path::Path) -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let file_contents = std::fs::read_to_string(path)?;

    let b64: &str = file_contents
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ioError::new(std::io::ErrorKind::InvalidInput, "invalid ssh key"))?;

    let decode = BASE64_STANDARD.decode(b64)?;

    read_inner_fields(&decode, 0);

    return parse_pub_key(&decode);
}

fn parse_pub_key(bytes: &Vec<u8>) -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let get_next_four_bytes = |i: &mut usize| {
        let mut x: u32 = 0;

        if *i + 3 >= bytes.len() {
            return None;
        }
        for j in *i..(*i + 3) {
            x += bytes[j] as u32;
            x <<= 8;
        }

        *i += 4; // set to first byte of new data

        Some(x + bytes[*i - 1] as u32)
    };

    let mut ind: usize = 0;
    let mut len = get_next_four_bytes(&mut ind);

    let mut found_nums: Vec<BigUint> = Vec::with_capacity(3);

    while len.is_some() {
        let l = len.unwrap() as usize;
        if ind + l > bytes.len() {
            break;
        }

        let data = BigUint::from_bytes_le(&bytes[ind..ind + l]);

        found_nums.push(data);

        ind += l;
        len = get_next_four_bytes(&mut ind);
    }

    if found_nums.len() != 3 {
        return Err(Box::new(ioError::new(
            std::io::ErrorKind::InvalidInput,
            "invalid ssh public key format",
        )));
    }

    found_nums.pop();
    Ok((found_nums.pop().unwrap(), found_nums.pop().unwrap()))
}

pub fn read_private_file(path: &std::path::Path) -> Result<(BigUint, BigUint), Box<dyn Error>> {
    let file_contents = std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let decode = BASE64_STANDARD.decode(file_contents)?;

    let first_section = &decode[0..AUTH_MAGIC_STR.len()];

    if !first_section.iter().eq(AUTH_MAGIC_STR.as_bytes()) {
        return Err(Box::new(ioError::new(
            std::io::ErrorKind::InvalidInput,
            "invalid ssh private key format",
        )));
    }

    let get_next_four_bytes = |i: &mut usize| {
        let mut x: u32 = 0;

        if *i + 3 >= decode.len() {
            return None;
        }
        for j in *i..(*i + 3) {
            x += decode[j] as u32;
            x <<= 8;
        }

        *i += 4; // set to first byte of new data

        Some(x + decode[*i - 1] as u32)
    };

    let mut ind: usize = 39; // skip first 39 bytes
    let mut len = get_next_four_bytes(&mut ind);

    let mut found_nums: Vec<BigUint> = Vec::with_capacity(3);

    while len.is_some() {
        let l = len.unwrap() as usize;
        if ind + l > decode.len() {
            break;
        }

        found_nums.push(BigUint::from_bytes_le(&decode[ind..ind + l]));

        ind += l;
        len = get_next_four_bytes(&mut ind);
    }

    if found_nums.len() < 2 {
        return Err(Box::new(ioError::new(
            std::io::ErrorKind::InvalidInput,
            "invalid ssh private key format",
        )));
    }

    let sk = found_nums.pop().unwrap().to_bytes_le();
    let pk = found_nums.pop().unwrap().to_bytes_le();

    // println!("private key hex: ({} bytes)", sk.len());
    // for b in sk.chunks(16) {
    //     for i in b {
    //         print!("{:#04x} ", i);
    //     }
    //     println!("")
    // }

    read_inner_fields(&sk, 8);

    Ok(parse_pub_key(&pk)?)
}

fn read_inner_fields(bytes: &Vec<u8>, start_ind: usize) {
    let next_four_to_u32 = |i: &mut usize| {
        let mut x: u32 = 0;

        if *i + 3 >= bytes.len() {
            return None;
        }
        for j in *i..(*i + 3) {
            x += bytes[j] as u32;
            x <<= 8;
        }

        *i += 4; // set to first byte of new data

        Some(x + bytes[*i - 1] as u32)
    };

    let mut ind = start_ind;
    let mut len = next_four_to_u32(&mut ind);

    let mut counter = 0;
    while len.is_some() {
        counter += 1;
        let l = len.unwrap() as usize;
        if ind + l > bytes.len() {
            break;
        }

        println!(
            "field {}: {}",
            counter,
            BigUint::from_bytes_le(&bytes[ind..ind + l])
        );

        ind += l;
        len = next_four_to_u32(&mut ind);
    }
}
