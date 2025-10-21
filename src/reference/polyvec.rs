#![allow(clippy::precedence)]
use crate::reference::poly::*;
use crate::params::*;


#[derive(Clone)]
pub struct Polyvec {
    pub vec: [Poly; KYBER_K],
}

impl Copy for Polyvec {}

impl Polyvec {
    pub fn new() -> Self {
        Polyvec {
            vec: [Poly::new(); KYBER_K],
        }
    }
}

/// Name:  polyvec_tobytes
///
/// Description: Serialize vector of polynomials
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVECBYTES)
///  - const Polyvec a: input vector of polynomials
pub fn polyvec_tobytes(r: &mut [u8], a: &Polyvec) {
    for i in 0..KYBER_K {
        poly_tobytes(&mut r[i * KYBER_POLYBYTES..], a.vec[i]);
    }
}

/// Name:  polyvec_frombytes
///
/// Description: De-serialize vector of polynomials;
///  inverse of polyvec_tobytes
///
/// Arguments:   - [u8] r: output byte array
///  - const Polyvec a: input vector of polynomials (of length KYBER_POLYVECBYTES)
pub fn polyvec_frombytes(r: &mut Polyvec, a: &[u8]) {
    for i in 0..KYBER_K {
        poly_frombytes(&mut r.vec[i], &a[i * KYBER_POLYBYTES..]);
    }
}

/// Name:  polyvec_reduce
///
/// Description: Applies Barrett reduction to each coefficient
///  of each element of a vector of polynomials
///  for details of the Barrett reduction see comments in reduce.c
///
/// Arguments:   - poly *r:   input/output polynomial
pub fn polyvec_reduce(r: &mut Polyvec) {
    for i in 0..KYBER_K {
        poly_reduce(&mut r.vec[i]);
    }
}

/// Name:  polyvec_add
///
/// Description: Add vectors of polynomials
///
/// Arguments: - Polyvec r:   output vector of polynomials
///  - const Polyvec b: second input vector of polynomials
pub fn polyvec_add(r: &mut Polyvec, b: &Polyvec) {
    for i in 0..KYBER_K {
        poly_add(&mut r.vec[i], &b.vec[i]);
    }
}

/// Name:  polyvec_sub
///
/// Description: Subtract vectors of polynomials
///
/// Arguments: - Polyvec r:   output vector of polynomials
///            - const Polyvec b: second input vector of polynomials
pub fn polyvec_sub(r: &mut Polyvec, b: &Polyvec) {
    for i in 0..KYBER_K {
        poly_sub(&mut r.vec[i], &b.vec[i]);
    }
}
