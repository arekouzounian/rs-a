//! Utility functions
use num::{BigUint, Integer};
use num_bigint::RandBigInt;
use rand::prelude::*;

use crate::keygen::{RsaCsprng, RSA_PRIME_NUMBER_BIT_LENGTH};

/// Generate a candidate prime (see `keygen.rs` for bit length)
/// Applies the Miller-Rabin Primality test `mr_iterations` times to test for primality.
///
/// `rng`: The CSPRNG used to generate primes
///
/// `mr_iterations`: The number of miller-rabin primality test iterations to conduct, default 1.
pub fn generate_candidate_prime(rng: &mut Box<dyn RsaCsprng>, mr_iterations: usize) -> BigUint {
    let mut num = generate_random_odd_big_uint(rng);

    let mut it = 1;

    while !miller_rabin_is_prime(rng, &num, mr_iterations) {
        num = generate_random_odd_big_uint(rng);
        it += 1;
    }

    dbg!("Total iterations necessary: {}", it);

    num
}

/// Generates a large, odd integer
pub fn generate_random_odd_big_uint(rng: &mut Box<dyn RsaCsprng>) -> BigUint {
    let x = rng.gen_biguint(RSA_PRIME_NUMBER_BIT_LENGTH);

    if x.bit(0) == true {
        return x;
    }

    x - 1u32
}

pub fn carmichael_totient(p: &BigUint, q: &BigUint) -> BigUint {
    (p - 1u32).lcm(&(q - 1u32))
}

// Miller-Rabin Primality Test
// A candidate prime p is an integer that we want to test for primality.
// A successful candidate will be an odd integer.
// Every odd prime can be decomposed into the form (p - 1) = 2^u * r, where r is an odd integer.
fn miller_rabin_is_prime(
    rng: &mut Box<dyn RsaCsprng>,
    prime_candidate: &BigUint,
    iterations: usize,
) -> bool {
    let two = BigUint::ZERO + 2u32;
    let one = BigUint::ZERO + 1u32;

    // if the prime candidate is even or 2 then we don't want to count it.
    if prime_candidate.eq(&two) || prime_candidate.modpow(&one, &two) == BigUint::ZERO {
        return false;
    }

    let p_minus_one = prime_candidate - 1u32;
    let mut u: u32 = 0;
    let mut r = p_minus_one.clone();

    while r.bit(0) == false {
        r = r >> 1;
        u += 1;
    }

    // assert!(p_minus_one == (two.pow(u) * r));

    for _ in 0..iterations {
        let a = rng.gen_biguint_range(&two, &p_minus_one);
        if test_witness(&a, &prime_candidate, u, &r) {
            return false;
        }
    }

    true
}

/// a: potential witness \
/// p: prime candidate \
/// r, u: values such that p - 1 = 2^u * r \
/// Returns true if a is a valid witness, false otherwise
fn test_witness(a: &BigUint, p: &BigUint, u: u32, r: &BigUint) -> bool {
    let mut z: BigUint = a.modpow(r, p);

    let two: BigUint = BigUint::ZERO + 2u32;
    let p_minus_one: BigUint = p - 1u32;

    if (&z - 1u32) == BigUint::ZERO {
        return false;
    }

    for i in 0..u {
        let exp = two.pow(i) * r;
        z = z.modpow(&exp, p);

        if z == p_minus_one {
            return false;
        }
    }

    true
}
