pub mod crypto;
pub mod errors;
pub mod keygen;
pub mod serial;
mod static_init;
mod util;

#[cfg(test)]
mod test {
    use crate::crypto::*;
    use crate::keygen::*;
    use crate::serial::*;
    use num::{BigUint, One};
    use num_bigint::RandBigInt;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use std::sync::OnceLock;

    static KP: OnceLock<KeyPair> = OnceLock::new();

    fn default_keypair() -> &'static KeyPair {
        KP.get_or_init(|| {
            KeyPairBuilder::default()
                .with_iterations(10)
                .create_keypair()
                .unwrap()
        })
    }

    #[test]
    fn generate_rsa_keypair_seeded() {
        const SEED: u64 = 100;

        let rng = Box::new(StdRng::seed_from_u64(SEED));

        let options = KeyPairBuilder::default()
            .with_rng(rng)
            .with_iterations(10)
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
    fn test_publickey_serial() {
        // TODO:
        //  - maybe change to pre-computed key from ssh-keygen?
        //  - add more error handling to serialization?

        let kp = default_keypair();

        let pk = kp.public_key.clone();

        let pk_serial = rsa_public_key_der_serialize(pk.clone());
        let pem_serial = pem_publickey_encode(pk_serial.clone());
        let pk_deserial = rsa_public_key_der_deserialize(pk_serial.clone());
        let pem_deserial = pem_decode(pem_serial);

        assert!(pk_deserial.is_ok());
        assert_eq!(pk, pk_deserial.unwrap());
        assert!(pem_deserial.is_ok());
        assert_eq!(pk_serial, pem_deserial.unwrap());
    }

    #[test]
    fn test_privatekey_serial() {
        let kp = default_keypair();
        let sk = kp.private_key.clone();

        let sk_serial = rsa_private_key_der_serialize(sk.clone());
        let pem_serial = pem_privatekey_encode(sk_serial.clone());
        let sk_deserial = rsa_private_key_der_deserialize(sk_serial.clone());
        let pem_deserial = pem_decode(pem_serial);

        assert!(sk_deserial.is_ok());
        assert_eq!(sk, sk_deserial.unwrap());
        assert!(pem_deserial.is_ok());
        assert_eq!(sk_serial, pem_deserial.unwrap());
    }
}
