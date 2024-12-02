//! Utility functions
use num::{BigUint, Integer, ToPrimitive};

use crate::keygen::{RsaCsprng, RSA_PRIME_NUMBER_BIT_LENGTH};
use crate::static_init::{PRECOMPUTED_PRIMES, PRECOMPUTED_PRIMES_LEN};

/// Generates a candidate prime (see `keygen.rs` for bit length) by repeated random drawing.
/// Applies the Miller-Rabin Primality test `mr_iterations` times to test for primality.
///
/// `rng`: The CSPRNG used to generate primes
///
/// `mr_iterations`: The number of miller-rabin primality test iterations to conduct, default 1.
pub fn generate_candidate_prime(rng: &mut Box<dyn RsaCsprng>, mr_iterations: usize) -> BigUint {
    let mut num = probable_prime(rng);
    while !miller_rabin_is_prime(rng, &num, mr_iterations) {
        num = probable_prime(rng);
    }

    num
}

/// Replicating the probable_prime() generation from OpenSSL
/// [See Source](https://github.com/openssl/openssl/blob/4a4505cc645d2e862e368e2823e921a564112ca2/crypto/bn/bn_prime.c#L487)
fn probable_prime(rng: &mut Box<dyn RsaCsprng>) -> BigUint {
    let mut mods: [u64; PRECOMPUTED_PRIMES_LEN] = [0; 512];
    const MAX_DELTA: u64 = u64::MAX - PRECOMPUTED_PRIMES[PRECOMPUTED_PRIMES_LEN - 1];

    'full_gen: loop {
        let mut candidate = generate_random_odd_big_uint(rng);

        for i in 1..PRECOMPUTED_PRIMES_LEN {
            mods[i] = (&candidate % PRECOMPUTED_PRIMES[i]).to_u64().unwrap();
        }

        let mut delta: u64 = 0;

        'check_mods: loop {
            for i in 1..PRECOMPUTED_PRIMES_LEN {
                if (mods[i] + delta) % PRECOMPUTED_PRIMES[i] == 0 {
                    delta += 2;
                    if delta > MAX_DELTA {
                        continue 'full_gen;
                    }
                    continue 'check_mods;
                }
            }
            break;
        }

        candidate += delta;
        if candidate.bits() != RSA_PRIME_NUMBER_BIT_LENGTH {
            continue;
        }

        return candidate;
    }
}

/// Generates a large, odd integer
/// Top 2 bits are always set
fn generate_random_odd_big_uint(rng: &mut Box<dyn RsaCsprng>) -> BigUint {
    let x = rng.gen_biguint(RSA_PRIME_NUMBER_BIT_LENGTH);

    if x.is_even() {
        return x - 1u32;
    }

    x
}

// Returns true if the prime candidate passes the prime sieve
// primes are defined in static_init
// fn small_prime_sieve(prime_candidate: &BigUint) -> bool {
//     for i in 1..PRECOMPUTED_PRIMES_LEN {
//         if prime_candidate % PRECOMPUTED_PRIMES[i] == BigUint::ZERO {
//             return false;
//         }
//     }

//     true
// }

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
        const NUM_ITER: usize = 1;

        let mut rng: Box<dyn RsaCsprng> = Box::new(StdRng::from_entropy());

        let mut times: [f64; NUM_ITER] = [0.0; NUM_ITER];

        let total = Instant::now();

        for i in times.iter_mut() {
            let start = Instant::now();
            // generate_candidate_prime(&mut rng, 1);
            probable_prime(&mut rng);
            let milli = start.elapsed().as_secs_f64();

            *i = milli;
        }

        println!(
            "Total elapsed time: {}s\nTotal iterations: {}\nAverage time per iteration: {}s\n",
            total.elapsed().as_secs_f64(),
            NUM_ITER,
            (times.iter().sum::<f64>()) / (NUM_ITER as f64)
        );

        // println!("{:?}", x);
    }
}
