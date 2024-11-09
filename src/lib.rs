use rand::prelude::*;

mod numbers;

pub fn generate_random_number() {
    let mut rng = StdRng::from_entropy();

    for _ in 0..10 {
        println!("{}", rng.next_u64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use numbers::prime_gen::generate_candidate_prime;

    #[test]
    fn gen_prime() {
        let mut rng = StdRng::from_entropy();

        println!("{}", generate_candidate_prime(&mut rng, 5));
    }
}
