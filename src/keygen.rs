//! Contains utilities for generating RSA keys.
//! Can generate keypairs using random number generation and primality testing, as well as
//! generating private keys from a given public key
use std::borrow::BorrowMut;

use num::{BigUint, Integer};
use num_bigint::RandBigInt;
use rand::{rngs::StdRng, CryptoRng, SeedableRng};

use crate::errors::RsaOptionsError;
use crate::util::{carmichael_totient, generate_candidate_prime, generate_prime_local_search};

pub const RSA_PRIME_NUMBER_BIT_LENGTH: u64 = 1024;
pub const RSA_MODULUS_BIT_LENGTH: usize = 2048;

pub const RSA_VERSION: RsaVersion = RsaVersion(0);

pub const DEFAULT_MR_ITERATIONS: usize = 1;

pub struct RsaVersion(u8);

pub trait RsaCsprng: CryptoRng + RandBigInt {}
impl<T: CryptoRng + RandBigInt> RsaCsprng for T {}

pub struct KeyPairBuilder {
    exponent: Option<BigUint>,
    modulus: Option<(BigUint, BigUint)>,
    rng: Option<Box<dyn RsaCsprng>>,
    mr_iterations: usize,
    local_generation: bool,
}

impl Default for KeyPairBuilder {
    fn default() -> Self {
        Self {
            exponent: None,
            modulus: None,
            rng: None,
            mr_iterations: DEFAULT_MR_ITERATIONS,
            local_generation: false,
        }
    }
}

impl KeyPairBuilder {
    pub fn with_exponent(&mut self, e: BigUint) -> &mut Self {
        self.exponent = Some(e);
        self
    }
    pub fn with_modulus(&mut self, p: BigUint, q: BigUint) -> &mut Self {
        self.modulus = Some((p, q));
        self
    }
    pub fn with_rng<R>(&mut self, rng: R) -> &mut Self
    where
        R: RsaCsprng + 'static,
    {
        self.rng = Some(Box::new(rng));
        self
    }
    pub fn with_iterations(&mut self, iterations: usize) -> &mut Self {
        self.mr_iterations = iterations;
        self
    }
    pub fn with_local_generation(&mut self) -> &mut Self {
        self.local_generation = true;
        self
    }

    /// Consumes fields
    pub fn create_keypair(&mut self) -> Result<KeyPair, RsaOptionsError> {
        let mut rng = self.rng.take().unwrap_or(Box::new(StdRng::from_entropy()));
        let mr_iterations = self.mr_iterations;

        dbg!("Generating modulus");
        let modulus = self.modulus.take().unwrap_or_else(|| {
            let p;
            let q;
            dbg!("Generating first prime...");

            if self.local_generation {
                p = generate_prime_local_search(&mut rng, mr_iterations);
                q = generate_prime_local_search(&mut rng, mr_iterations);
            } else {
                p = generate_candidate_prime(&mut rng, mr_iterations);
                q = generate_candidate_prime(&mut rng, mr_iterations);
            }

            (p, q)
        });

        dbg!("Computing totient...");
        let lambda = carmichael_totient(&modulus.0, &modulus.1);

        dbg!("Computing exponent...");
        let exponent = self.exponent.take().unwrap_or_else(|| {
            // compute carmichael totient = lambda
            // look for values of e that are coprime to lambda
            let three = BigUint::ZERO + 3u32;
            let one = BigUint::ZERO + 1u32;
            let mut e = rng.gen_biguint_range(&three, &lambda);

            // pick a random spot, look locally till we find something coprime to lambda
            // if we reach lambda then start over
            // should be faster than just generating randomly over and over
            while e.gcd(&lambda) != one {
                e.inc();

                if e == lambda {
                    e = rng.gen_biguint_range(&three, &lambda);
                }
            }

            e
        });

        dbg!("Computing secret...");
        let secret = exponent
            .modinv(&lambda)
            .ok_or(RsaOptionsError::new(format!(
                "Unable to find modular inverse of {} with respect to {}.",
                exponent, lambda
            )))?;

        let n = &modulus.0 * &modulus.1;

        let pk = RsaPublicKey::new(exponent.clone(), n.clone());
        let sk = RsaPrivateKey::with_values(n, exponent, secret, modulus.0, modulus.1)?;

        Ok(KeyPair {
            public_key: pk,
            private_key: sk,
        })
    }
}

pub struct KeyPair {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

pub struct RsaPublicKey {
    pub modulus: BigUint,
    pub public_exponent: BigUint,
}
/// [See source](https://datatracker.ietf.org/doc/html/rfc3447#appendix-A)
pub struct RsaPrivateKey {
    pub version: RsaVersion,
    pub modulus: BigUint,
    pub public_exponent: BigUint,
    pub private_exponent: BigUint,
    pub prime1: BigUint,
    pub prime2: BigUint,
    pub exponent1: BigUint,
    pub exponent2: BigUint,
    pub coefficient: BigUint,
}

impl RsaPublicKey {
    pub fn new(e: BigUint, n: BigUint) -> Self {
        Self {
            public_exponent: e,
            modulus: n,
        }
    }
}

impl RsaPrivateKey {
    fn with_values(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        p: BigUint,
        q: BigUint,
    ) -> Result<Self, RsaOptionsError> {
        let one = BigUint::ZERO + 1u32;
        let p1 = &p - 1u32;
        let q1 = &q - 1u32;

        let dp = d.modpow(&one, &p1);
        let dq = d.modpow(&one, &q1);
        let qinv = q.modinv(&p).ok_or(RsaOptionsError::new(format!(
            "Unable to compute modular inverse of {} with respect to {}.",
            q, p
        )))?;

        Ok(Self {
            version: RSA_VERSION,
            modulus: n,
            public_exponent: e,
            private_exponent: d,
            prime1: p,
            prime2: q,
            exponent1: dp,
            exponent2: dq,
            coefficient: qinv,
        })
    }
}
