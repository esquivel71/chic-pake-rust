#![no_std]

/// Self-contained, `no_std` SHA-256 implementation in pure Rust.
/// Public API:
///   - `sha256(data: &[u8]) -> [u8; 32]`
///   - `Sha256` struct with `new()`, `update()`, and `finalize()`
pub struct Sha256 {
    h: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 context
    pub const fn new() -> Self {
        Self {
            h: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    /// Update the hash with more data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.bit_len = self.bit_len.wrapping_add((data.len() as u64) * 8);

        // fill buffer if partially full
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            let take = needed.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // process full blocks directly
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            self.process_block(block.try_into().unwrap());
            data = rest;
        }

        // store remainder
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize and return the 32-byte hash digest
    pub fn finalize(mut self) -> [u8; 32] {
        let mut block = [0u8; 64];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        let mut len = self.buffer_len;

        // append the bit '1'
        block[len] = 0x80;
        len += 1;

        // if not enough space for 8-byte length field
        if len > 56 {
            for i in len..64 {
                block[i] = 0;
            }
            self.process_block(&block);
            len = 0;
        }

        // pad with zeros until byte 56
        for i in len..56 {
            block[i] = 0;
        }

        // append message length (64-bit big endian)
        let bit_len = self.bit_len.to_be_bytes();
        block[56..64].copy_from_slice(&bit_len);

        self.process_block(&block);

        // output final digest
        let mut out = [0u8; 32];
        for (i, &v) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut w = [0u32; 64];
        for t in 0..16 {
            let i = t * 4;
            w[t] = u32::from_be_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);
        }

        for t in 16..64 {
            w[t] = sigma1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(sigma0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        for t in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

/// One-shot SHA-256 hash function
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

// Internal helpers (per FIPS 180-4)
#[inline(always)] fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ ((!x) & z) }
#[inline(always)] fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
#[inline(always)] fn big_sigma0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
#[inline(always)] fn big_sigma1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
#[inline(always)] fn sigma0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }
#[inline(always)] fn sigma1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            write!(s, "{:02x}", b).unwrap();
        }
        s
    }

    #[test]
    fn test_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855"
        );

        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223\
             b00361a396177a9cb410ff61f20015ad"
        );

        assert_eq!(
            hex(&sha256(b"The quick brown fox jumps over the lazy dog")),
            "d7a8fbb307d7809469ca9abcb0082e4f\
             8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }
}
