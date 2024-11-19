# rs-a 
An implementation of RSA, as specified in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017), using Rust.

## Intended Usage
The goal of this project is to implement a basic RSA library that includes encryption, decryption, key generation, signature, and verification functions. 

This isn't intended to be a production-grade library; this is more of an exercise in writing Rust code, learning about RSA, and trying to write code that adheres to a written standard. 

While the library contained herein is intended to adhere to [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) as much as possible, the end-product is not designed to be used for commercial purposes, and it is very much likely that the library itself will not be in complete compliance with the RFC. For more specific language as to the purposes of this repository, consult the [license](LICENSE).

I am still very new to Rust, so this library is likely to be non-idiomatic. I'm also very new to the number theory behind RSA, so despite my attempts at making clean and correct code, this library isn't guaranteed to be very performant. 


# Goals: 
- 2 prime RSA
- 2048 bit modulus 

## Notes & Reference Materials 
- [RFC 8017 - PKCS1 v2.2](https://www.rfc-editor.org/rfc/rfc8017)
- [The usage of the CRT in RSA](https://www.di-mgt.com.au/crt_rsa.html)
- [Miller-Rabin Primality Testing](https://incolumitas.com/2018/08/12/finding-large-prime-numbers-and-rsa-miller-rabin-test/)
- [Prime testing website](https://bigprimes.org/primality-test)
- ["Elegant Library APIs in Rust"](https://deterministic.space/elegant-apis-in-rust.html)
- ["Idiomatic Rust Libraries" (Video)](https://www.youtube.com/watch?v=0zOg8_B71gE)
- [Rust Design Pattern](https://rust-unofficial.github.io/patterns/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Idiomatic Rust Resources](https://corrode.dev/blog/idiomatic-rust-resources/)