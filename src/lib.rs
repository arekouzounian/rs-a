pub mod crypto;
pub mod errors;
pub mod keygen;
pub mod util;

#[cfg(test)]
mod tests {
    use crate::crypto::*;
    use crate::keygen::*;
    use num::{BigUint, FromPrimitive};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn generate_rsa_keypair_random() {
        let rng: Box<dyn RsaCsprng> = Box::new(StdRng::from_entropy());

        let options = KeyPairBuilder::default()
            .with_rng(rng)
            .create_keypair()
            .inspect_err(|err| println!("{}", err));

        assert!(options.is_ok());
        let kp = options.unwrap();

        let pk = kp.public_key;
        let sk = kp.private_key;

        let p1 = &sk.prime1 - 1u32;
        let q1 = &sk.prime2 - 1u32;

        assert_eq!(&pk.public_exponent, &sk.public_exponent);
        assert_eq!(&pk.modulus, &sk.modulus);

        let one = BigUint::ZERO + 1u32;

        assert_eq!((&pk.public_exponent * &sk.exponent1) % &p1, one);
        assert_eq!((&pk.public_exponent * &sk.exponent2) % &q1, one);
    }

    #[test]
    fn generate_rsa_keypair_local() {
        let rng = Box::new(StdRng::from_entropy());

        let options = KeyPairBuilder::default()
            .with_rng(rng)
            .with_prime_gen_method(PrimeGenMethod::RandomizedLocalSearch)
            .create_keypair()
            .inspect_err(|err| println!("{}", err));

        assert!(options.is_ok());
        let kp = options.unwrap();

        let pk = kp.public_key;
        let sk = kp.private_key;

        let p1 = &sk.prime1 - 1u32;
        let q1 = &sk.prime2 - 1u32;

        assert_eq!(&pk.public_exponent, &sk.public_exponent);
        assert_eq!(&pk.modulus, &sk.modulus);

        let one = BigUint::ZERO + 1u32;

        assert_eq!((&pk.public_exponent * &sk.exponent1) % &p1, one);
        assert_eq!((&pk.public_exponent * &sk.exponent2) % &q1, one);

        let m = BigUint::from_u32(100).unwrap();

        let cipher_res = pk.crypt(&m);
        assert!(cipher_res.is_ok());

        let c = cipher_res.unwrap();

        let decrypt_res = sk.crypt(&c);
        assert!(decrypt_res.is_ok());

        let d = decrypt_res.unwrap();

        assert_eq!(m, d);
    }
}
