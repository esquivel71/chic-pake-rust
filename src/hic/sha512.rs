#![no_std]

/// Self-contained, `no_std` SHA-512 implementation in pure Rust.
/// Public API:
///   - `sha512(data: &[u8]) -> [u8; 64]`
///   - `Sha512` struct with `new()`, `update()`, `finalize()`
pub struct Sha512 {
    h: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    bit_len: u128,
}

impl Sha512 {
    /// Create a new SHA-512 context
    pub const fn new() -> Self {
        Self {
            h: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0; 128],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    /// Update the hash with a new chunk of data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.bit_len = self.bit_len.wrapping_add((data.len() as u128) * 8);

        // fill buffer if partial
        if self.buffer_len > 0 {
            let needed = 128 - self.buffer_len;
            let take = needed.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == 128 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // process full blocks directly
        while data.len() >= 128 {
            let (block, rest) = data.split_at(128);
            let mut block2 = [0u8;128];
            block2.copy_from_slice(&block[..128]);
            self.process_block(&block2);
            data = rest;
        }

        // store remainder
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize the hash and return the 64-byte digest
    pub fn finalize(mut self) -> [u8; 64] {
        let mut block = [0u8; 128];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        let mut len = self.buffer_len;

        // append the bit '1'
        block[len] = 0x80;
        len += 1;

        // if not enough space for 16-byte length field
        if len > 112 {
            for i in len..128 {
                block[i] = 0;
            }
            self.process_block(&block);
            len = 0;
        }

        // pad with zeros until byte 112
        for i in len..112 {
            block[i] = 0;
        }

        // append 128-bit length (big endian)
        let bit_len = self.bit_len.to_be_bytes();
        block[112..128].copy_from_slice(&bit_len);

        self.process_block(&block);

        // produce digest
        let mut out = [0u8; 64];
        for (i, hv) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&hv.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 128]) {
        const K: [u64; 80] = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        ];

        let mut w = [0u64; 80];
        for t in 0..16 {
            let i = t * 8;
            w[t] = u64::from_be_bytes([
                block[i], block[i + 1], block[i + 2], block[i + 3],
                block[i + 4], block[i + 5], block[i + 6], block[i + 7],
            ]);
        }

        for t in 16..80 {
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

        for t in 0..80 {
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

/// Convenience function for one-shot hashing
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

// --- internal helpers ---
#[inline(always)] fn ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ ((!x) & z) }
#[inline(always)] fn maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
#[inline(always)] fn big_sigma0(x: u64) -> u64 { x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39) }
#[inline(always)] fn big_sigma1(x: u64) -> u64 { x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41) }
#[inline(always)] fn sigma0(x: u64) -> u64 { x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7) }
#[inline(always)] fn sigma1(x: u64) -> u64 { x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6) }

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
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc\
             83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f\
             63b931bd47417a81a538327af927da3e"
        );

        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2\
             0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        );

        assert_eq!(
            hex(&sha512(b"hello, this is patrick")),
            "606470c7243c69953f6ace64469d761df26230a126daa54ca\
             b261dc3d3e287945de061f4f31bfc692dbe97e4fa229ef4cd\
             49d0cd57d33f15bbd991f825833181"
        )
    }
}