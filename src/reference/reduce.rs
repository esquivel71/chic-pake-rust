use crate::params::KYBER_Q;

/// Name:  barrett_reduce
///
/// Description: Barrett reduction; given a 16-bit integer a, computes
///  centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
///
/// Arguments:   - i16 a: input integer to be reduced
///
/// Returns:   i16 in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
pub fn barrett_reduce(a: i16) -> i16 {
    let v = ((1u32 << 26) / KYBER_Q as u32 + 1) as i32;
    let mut t = v * a as i32 + (1 << 25);
    t >>= 26;
    t *= KYBER_Q as i32;
    a - t as i16
}
