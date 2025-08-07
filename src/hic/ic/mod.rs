pub mod constants;
pub mod rijndael;
pub mod errors;

pub fn ic256_enc(block: &mut [u8;32], key: &[u8;32]) {
    // Initialize cipher
    let cipher = rijndael::Rijndael::new(key, 32).unwrap();
    let enc_block = cipher.encrypt(block).unwrap();
    block[0..32].copy_from_slice(&enc_block);
}

pub fn ic256_dec(enc_block: &mut [u8;32], key: &[u8;32]) {
    // Initialize cipher
    let cipher = rijndael::Rijndael::new(key, 32).unwrap();
    let block = cipher.decrypt(enc_block).unwrap();
    enc_block[0..32].copy_from_slice(&block);
}