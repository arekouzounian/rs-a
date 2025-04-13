use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rand::{rngs::StdRng, SeedableRng};
use rs_a::{
    crypto::RsaPrimitive,
    keygen::{KeyPairBuilder, RsaCsprng},
    util::{carmichael_totient, generate_candidate_prime, miller_rabin_is_prime},
};

use num::{BigUint, Integer};
use num_bigint::RandBigInt;

const MILLER_RABIN_ITERATIONS: usize = 10;

// Generates a candidate prime.
pub fn candidate_prime_benchmark(c: &mut Criterion) {
    let mut rng: Box<dyn RsaCsprng> = Box::new(StdRng::from_entropy());
    const ITERATIONS: usize = 10;

    c.bench_function("candidate primes", |b| {
        b.iter(|| {
            black_box(generate_candidate_prime(&mut rng, ITERATIONS));
        })
    });
}

// computes `PRIMES` primes, then performs the Miller-Rabin
// Primality test on each prime with `ITERATIONS` iterations
// on each prime.
pub fn miller_rabin_benchmark(c: &mut Criterion) {
    const PRIMES: usize = 10;
    let mut rng: Box<dyn RsaCsprng> = Box::new(StdRng::from_entropy());
    let mut candidates = Vec::<BigUint>::with_capacity(PRIMES);
    let mut group = c.benchmark_group("miller_rabin");

    for _ in 0..PRIMES {
        candidates.push(generate_candidate_prime(&mut rng, MILLER_RABIN_ITERATIONS));
    }

    group.bench_function("miller-rabin", |b| {
        b.iter(|| {
            black_box(
                candidates
                    .iter()
                    .map(|c| miller_rabin_is_prime(&mut rng, c, MILLER_RABIN_ITERATIONS))
                    .fold(0, |acc, b| if !b { acc + 1 } else { acc }),
            )
        })
    });
}

// Generates a keypair
pub fn keypair_builder_benchmark(c: &mut Criterion) {
    c.bench_function("keypair generation", |b| {
        b.iter(|| {
            KeyPairBuilder::default()
                .with_iterations(MILLER_RABIN_ITERATIONS)
                .create_keypair()
        })
    });
}

pub fn encryption_decryption_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption & decryption primitives");

    let kp = KeyPairBuilder::default().create_keypair().unwrap();
    let mut rng = StdRng::from_entropy();

    const BIT_SIZE: u64 = 1024;

    group.bench_function("encryption primitive", |b| {
        b.iter(|| {
            let m = rng.gen_biguint(BIT_SIZE);
            black_box(&kp.public_key.crypt(&m).unwrap());
        })
    });

    group.bench_function("decryption primitive (CRT)", |b| {
        b.iter(|| {
            let m = rng.gen_biguint(BIT_SIZE);

            black_box(&kp.private_key.crypt(&m).unwrap());
        })
    });

    group.bench_function("decryption primitive (exponent)", |b| {
        b.iter(|| {
            let m = rng.gen_biguint(BIT_SIZE);
            black_box(m.modpow(&kp.private_key.private_exponent, &kp.private_key.modulus))
        })
    });

    group.bench_function("encrypt decrypt", |b| {
        b.iter(|| {
            let m = rng.gen_biguint(BIT_SIZE);

            let e = &kp.public_key.crypt(&m).unwrap();
            let d = &kp.private_key.crypt(&e).unwrap();

            assert_eq!(*d, m);
        })
    });
}

// Computes public and private exponents on two precomputed primes.
pub fn exponent_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("modular exponentiation");

    let mut rng: Box<dyn RsaCsprng> = Box::new(StdRng::from_entropy());

    let p = generate_candidate_prime(&mut rng, MILLER_RABIN_ITERATIONS);
    let q = generate_candidate_prime(&mut rng, MILLER_RABIN_ITERATIONS);

    let lambda = carmichael_totient(&p, &q);

    let three = BigUint::ZERO + 3u32;
    let one = BigUint::ZERO + 1u32;

    group.bench_function("compute public exponent", |b| {
        b.iter(|| {
            let mut e = rng.gen_biguint_range(&three, &lambda);
            while e.gcd(&lambda) != one {
                e.inc();

                if e == lambda {
                    e = rng.gen_biguint_range(&three, &lambda);
                }
            }
        })
    });

    let mut e = rng.gen_biguint_range(&three, &lambda);
    while e.gcd(&lambda) != one {
        e.inc();

        if e == lambda {
            e = rng.gen_biguint_range(&three, &lambda);
        }
    }

    group.bench_function("compute secret exponent", |b| {
        b.iter(|| {
            e.modinv(&lambda);
        })
    });

    group.finish();
}

// [See Docs](https://bheisler.github.io/criterion.rs/book/user_guide/advanced_configuration.html)
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(250);
    targets = candidate_prime_benchmark, miller_rabin_benchmark, keypair_builder_benchmark, exponent_benchmark, encryption_decryption_bench
    // targets = encryption_decryption_bench
}
criterion_main!(benches);
