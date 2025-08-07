# RUST implementation of CHIC

This repository contains a reference Rust implementation of the CHIC Post-Quantum PAKE. The original reference implementation in C, from the [paper](https://eprint.iacr.org/2024/308) can be seen [here](https://github.com/mbbarbosa/chic-pake).

The CHIC PAKE uses ML-KEM for key encapsulation. This implementation can use any Rust-based implementation or wrapper of ML-KEM, by passing the keygen, encapsulate and decapsulate functions as parameters to init_start, resp and init_end respectively.
