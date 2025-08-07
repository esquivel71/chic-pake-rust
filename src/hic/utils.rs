use crate::{params::{KYBER_N,KYBER_K,KYBER_Q}, reference::polyvec::Polyvec, symmetric::{xof_absorb, xof_squeezeblocks, XofState, XOF_BLOCKBYTES}};

/// Name:  rej_uniform
///
/// Description: Run rejection sampling on uniform random bytes to generate
///  uniform random integers mod q
/// 
/// Results:    - [i16] r: output buffer
///
/// Arguments:  - usize len: requested number of 16-bit integers (uniform mod q)
///             - [u8] buf: input buffer (assumed to be uniform random bytes)
///             - usize buflen: length of input buffer in bytes
///
/// Return values: number of sampled 16-bit integers (at most len)
fn rej_uniform(r: &mut [i16], len: usize, buf: &[u8], buflen: usize) -> usize {
    let (mut ctr, mut pos) = (0usize, 0usize);
    let (mut val0, mut val1);

    while ctr < len && pos + 3 <= buflen {
        val0 = ((buf[pos + 0] >> 0) as u16 | (buf[pos + 1] as u16) << 8) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) as u16 | (buf[pos + 2] as u16) << 4) & 0xFFF;
        pos += 3;

        if val0 < KYBER_Q as u16 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < len && val1 < KYBER_Q as u16 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

/// Name:  gen_vector
///
/// Description: Deterministically generate vector v from a seed. Entries of the vector are polynomials that look uniformly random. Performs rejection sampling on output of a XOF
/// 
/// Results:     - Polyvec icc: output vector v
///
/// Arguments:   - [u8] seed: input seed
pub fn gen_vector(v: &mut Polyvec, seed: &[u8]) {
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;
    let mut ctr: usize;
    let (mut buflen, mut off): (usize,usize);
    let mut buf = [0u8;GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
    let mut state = XofState::new();

    for i in 0..KYBER_K {
        xof_absorb(&mut state, seed, i as u8, 0u8); //take row 0
        xof_squeezeblocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state);
        buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
        ctr = rej_uniform(&mut v.vec[i].coeffs, KYBER_N, &buf, buflen);

        while ctr < KYBER_N {
            off = buflen % 3;
            for k in 0..off {
                buf[k] = buf[buflen - off + k];
            }
            xof_squeezeblocks(&mut buf[off..], 1, &mut state);
            buflen = off + XOF_BLOCKBYTES;
            ctr += rej_uniform(&mut v.vec[i].coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
        }
    }     
}