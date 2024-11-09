# rs-a 
An implementation of RSA, as specified in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017), using Rust.

## Intended Usage
The goal of this project is to implement a basic RSA library that includes encryption, decryption, key generation, signature, and verification functions. 

This isn't intended to be a production-grade library; this is more of an exercise in writing Rust code, learning about RSA, and trying to write code that adheres to a written standard. 

While the library contained herein is intended to adhere to [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) as much as possible, the end-product is not designed to be used for commercial purposes, and it is very much likely that the library itself will not be in complete compliance with the RFC. For more specific language as to the purposes of this repository, consult the [license](LICENSE).


# Goals: 
- 2 prime RSA
- 2048 bit modulus 

## Notes & Reference Materials 
- [RFC 8017 - PKCS1 v2.2](https://www.rfc-editor.org/rfc/rfc8017)
- [The usage of the CRT in RSA](https://www.di-mgt.com.au/crt_rsa.html)
- [Miller-Rabin Primality Testing](https://incolumitas.com/2018/08/12/finding-large-prime-numbers-and-rsa-miller-rabin-test/)