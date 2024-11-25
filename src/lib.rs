pub mod crypto;
pub mod errors;
pub mod keygen;
pub mod serial;
pub mod util;

#[cfg(test)]
mod tests {
    use crate::crypto::*;
    use crate::keygen::*;
    use crate::serial::*;
    use num::{BigUint, One};
    use num_bigint::RandBigInt;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use std::path::Path;
    use std::sync::OnceLock;

    static KP: OnceLock<KeyPair> = OnceLock::new();

    fn default_keypair() -> &'static KeyPair {
        KP.get_or_init(|| {
            KeyPairBuilder::default()
                .with_iterations(5)
                .create_keypair()
                .unwrap()
        })
    }

    #[test]
    fn generate_rsa_keypair_local_search() {
        let kp = default_keypair();

        let pk = &kp.public_key;
        let sk = &kp.private_key;

        let p1 = &sk.prime1 - 1u32;
        let q1 = &sk.prime2 - 1u32;

        assert_eq!(&pk.public_exponent, &sk.public_exponent);
        assert_eq!(&pk.modulus, &sk.modulus);

        let one = BigUint::ZERO + 1u32;

        assert_eq!((&pk.public_exponent * &sk.exponent1) % &p1, one);
        assert_eq!((&pk.public_exponent * &sk.exponent2) % &q1, one);
    }

    #[test]
    fn generate_rsa_keypair_random() {
        let rng = Box::new(StdRng::from_entropy());

        let options = KeyPairBuilder::default()
            .with_rng(rng)
            .with_prime_gen_method(PrimeGenMethod::RandomGeneration)
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
    fn test_encryption_decryption() {
        let kp = default_keypair();

        let mut rng = StdRng::from_entropy();

        let m = rng.gen_biguint_range(&BigUint::one(), &kp.private_key.modulus);

        let cipher_res = kp.public_key.crypt(&m);
        assert!(cipher_res.is_ok());

        let c = cipher_res.unwrap();

        let decrypt_res = kp.private_key.crypt(&c);
        assert!(decrypt_res.is_ok());

        let d = decrypt_res.unwrap();

        println!(
            "p: {}\nq: {}",
            &kp.private_key.prime1, &kp.private_key.prime2
        );

        assert_eq!(m, d);
    }

    #[test]
    fn test_serial() {
        let res = read_ssh_public_key(Path::new("/Users/arekouzounian/.ssh/id_rsa.pub"));
        assert!(res.is_ok());

        let kp = res.unwrap();

        println!("exponent: {}", kp.0);
        println!("modulus: {}", kp.1);

        let ret = read_private_file(Path::new("/Users/arekouzounian/.ssh/id_rsa"));
        assert!(ret.is_ok());

        // let (sk, pk) = ret.unwrap();

        // println!("modulus: {}", pk);
        // println!("exponent: {}", sk);

        // let tup = res.unwrap();

        // let options = RsaPublicKey::new(tup.0, tup.1);
    }
}
