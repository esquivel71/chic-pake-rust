use crate::reference::{reduce::*};
use crate::{params::*};

#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i16; KYBER_N],
}

impl Copy for Poly {}

impl Default for Poly {
    fn default() -> Self {
        Poly {
            coeffs: [0i16; KYBER_N],
        }
    }
}

// new() is nicer
impl Poly {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Name:  poly_tobytes
///
/// Description: Serialization of a polynomial
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYBYTES bytes)
///  - const poly *a:  input polynomial
pub fn poly_tobytes(r: &mut [u8], a: Poly) {
    let (mut t0, mut t1);

    for i in 0..(KYBER_N / 2) {
        // map to positive standard representatives
        t0 = a.coeffs[2 * i];
        t0 += (t0 >> 15) & KYBER_Q as i16;
        t1 = a.coeffs[2 * i + 1];
        t1 += (t1 >> 15) & KYBER_Q as i16;
        r[3 * i + 0] = (t0 >> 0) as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// Name:  poly_frombytes
///
/// Description: De-serialization of a polynomial;
///  inverse of poly_tobytes
///
/// Arguments:   - poly *r:  output polynomial
///  - const [u8] a: input byte array (of KYBER_POLYBYTES bytes)
pub fn poly_frombytes(r: &mut Poly, a: &[u8]) {
    for i in 0..(KYBER_N / 2) {
        r.coeffs[2 * i + 0] =
            ((a[3 * i + 0] >> 0) as u16 | ((a[3 * i + 1] as u16) << 8) & 0xFFF) as i16;
        r.coeffs[2 * i + 1] =
            ((a[3 * i + 1] >> 4) as u16 | ((a[3 * i + 2] as u16) << 4) & 0xFFF) as i16;
    }
}

/// Name:  poly_reduce
///
/// Description: Applies Barrett reduction to all coefficients of a polynomial
///  for details of the Barrett reduction see comments in reduce.c
///
/// Arguments:   - poly *r:   input/output polynomial
pub fn poly_reduce(r: &mut Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = barrett_reduce(r.coeffs[i]);
    }
}

/// Name:  poly_add
///
/// Description: Add two polynomials; no modular reduction is performed
///
/// Arguments: - poly *r:   output polynomial
///  - const poly *a: first input polynomial
///  - const poly *b: second input polynomial
pub fn poly_add(r: &mut Poly, b: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] += b.coeffs[i];
    }
}

/// Name:  poly_sub
///
/// Description: Subtract two polynomials; no modular reduction is performed
///
/// Arguments: - poly *r:   output polynomial
///  - const poly *a: first input polynomial
///  - const poly *b: second input polynomial
pub fn poly_sub(r: &mut Poly, a: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = a.coeffs[i] - r.coeffs[i];
    }
}
