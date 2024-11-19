pub mod crypto;
mod errors;
pub mod keygen;
mod util;

#[cfg(test)]
mod tests {
    use crate::keygen::*;
    use num::BigUint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn generate_rsa_keypair() {
        let rng = StdRng::from_entropy();

        let options = RsaOptions::default()
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
}
