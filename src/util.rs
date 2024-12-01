//! Utility functions

use num::{BigUint, Integer};

use crate::keygen::{RsaCsprng, RSA_PRIME_NUMBER_BIT_LENGTH};

/// Generates a candidate prime (see `keygen.rs` for bit length) by repeated random drawing.
/// Applies the Miller-Rabin Primality test `mr_iterations` times to test for primality.
///
/// `rng`: The CSPRNG used to generate primes
///
/// `mr_iterations`: The number of miller-rabin primality test iterations to conduct, default 1.
pub fn generate_candidate_prime(rng: &mut Box<dyn RsaCsprng>, mr_iterations: usize) -> BigUint {
    let mut num = generate_random_odd_big_uint(rng);

    while !miller_rabin_is_prime(rng, &num, mr_iterations) {
        num = generate_random_odd_big_uint(rng);
    }

    num
}

/// Generates a candidate prime (see `keygen.rs` for bit length) by an initial random
/// drawing, and then continuous incrementation (local search).
/// Applies the Miller-Rabin Primality test `mr_iterations` times to test for primality.
///
/// `rng`: The CSPRNG used to generate primes
///
/// `mr_iterations`: The number of miller-rabin primality test iterations to conduct,
/// default 1.
pub fn generate_prime_local_search(rng: &mut Box<dyn RsaCsprng>, mr_iterations: usize) -> BigUint {
    let mut num = generate_random_odd_big_uint(rng);

    while !(miller_rabin_is_prime(rng, &num, mr_iterations)) {
        num += 2u32;
    }

    num
}

/// Generates a large, odd integer
fn generate_random_odd_big_uint(rng: &mut Box<dyn RsaCsprng>) -> BigUint {
    let x = rng.gen_biguint(RSA_PRIME_NUMBER_BIT_LENGTH);

    if x.bit(0) == true {
        return x;
    }

    x - 1u32
}

/// Computes the Carmichael Totient function `lambda(n)` for a given two-prime RSA modulus,
/// represented by primes `p, q`.
pub fn carmichael_totient(p: &BigUint, q: &BigUint) -> BigUint {
    (p - 1u32).lcm(&(q - 1u32))
}

// Miller-Rabin Primality Test
// A candidate prime p is an integer that we want to test for primality.
// A successful candidate will be an odd integer.
// Every odd prime can be decomposed into the form (p - 1) = 2^u * r,
// where r is an odd integer.
fn miller_rabin_is_prime(
    rng: &mut Box<dyn RsaCsprng>,
    prime_candidate: &BigUint,
    iterations: usize,
) -> bool {
    let two = BigUint::ZERO + 2u32;
    let one = BigUint::ZERO + 1u32;

    if prime_candidate.eq(&BigUint::ZERO) {
        return false;
    }

    // if the prime candidate is even or 2 then we don't want to count it.
    if prime_candidate.eq(&two) || prime_candidate.modpow(&one, &two) == BigUint::ZERO {
        return false;
    }

    let p_minus_one = prime_candidate - 1u32;

    let u = p_minus_one.trailing_zeros().unwrap() as u32;
    let r = &p_minus_one >> u;

    // assert!(p_minus_one == (two.pow(u) * &r));

    for _ in 0..iterations {
        let a = rng.gen_biguint_range(&two, &p_minus_one);
        if test_witness(&a, &prime_candidate, &u, &r) {
            return false;
        }
    }

    true
}

/// `a`: potential witness \
/// `p`: prime candidate \
/// `r, u`: values such that `p - 1` = `2^u * r` \
/// Returns true if a is a valid witness, false otherwise
fn test_witness(a: &BigUint, p: &BigUint, u: &u32, r: &BigUint) -> bool {
    let mut z: BigUint = a.modpow(r, p);

    let two: BigUint = BigUint::ZERO + 2u32;
    let p_minus_one: BigUint = p - 1u32;

    if (&z - 1u32) == BigUint::ZERO {
        return false;
    }

    for i in 0..*u {
        let exp = two.pow(i) * r;
        z = z.modpow(&exp, p);

        if z == p_minus_one {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::prelude::*;
    use std::time::Instant;

    #[test]
    fn benchmark() {
        const NUM_ITER: usize = 10;

        let mut rng: Box<dyn RsaCsprng> = Box::new(StdRng::from_entropy());

        let mut times: [u128; NUM_ITER] = [0; NUM_ITER];

        let p = generate_prime_local_search(&mut rng, 6);
        println!("candidate found, performing benchmark");

        let total = Instant::now();

        for i in times.iter_mut() {
            let start = Instant::now();
            miller_rabin_is_prime(&mut rng, &p, 5);
            let milli = start.elapsed().as_millis();

            *i = milli;
        }

        println!(
            "Total elapsed time: {}\nTotal iterations: {}\nAverage time per iteration: {}\n",
            total.elapsed().as_millis(),
            NUM_ITER,
            (times.iter().sum::<u128>() as f64) / (NUM_ITER as f64)
        );

        // println!("{:?}", x);
    }
}
