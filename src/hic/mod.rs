use crate::{reference::polyvec::{polyvec_add, polyvec_frombytes, polyvec_reduce, polyvec_sub, polyvec_tobytes, Polyvec}, KyberError};
use crate::{symmetric::hash_h,params::*};

mod ic;
mod utils;
pub mod sha512_nostd;
pub mod sha256_nostd;

/// Name:  hic_eval
///
/// Description: Computes the "half-ideal cipher" over a Kyber pk
/// 
/// Results:     - [u8] icc: output ciphertext (of length KYBER_PUBLICKEYBYTES bytes)
///
/// Arguments:   - [u8] pk: the input public key (of length KYBER_PUBLICKEYBYTES bytes)
///              - [u8] pw: input password (of length KYBER_SYMBYTES bytes)
///              - [u8] sid: input sid (of length KYBER_SYMBYTES bytes)
pub fn hic_eval(
    icc: &mut [u8;KYBER_PUBLICKEYBYTES],
    pk: &[u8;KYBER_PUBLICKEYBYTES],
    pw: &[u8;KYBER_SYMBYTES],
    sid: &[u8;KYBER_SYMBYTES]
) -> Result<(),KyberError>
{
    let mut hash_in_lr = [0u8;3*KYBER_SYMBYTES];
    let mut hash_in_rl = [0u8;2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES];
    let mut in_rho = [0u8;KYBER_SYMBYTES];
    let mut key = [0u8;KYBER_SYMBYTES];
    let mut mask_seed_t = [0u8;KYBER_SYMBYTES];
    let (mut in_t,mut mask_t) = (Polyvec::new(), Polyvec::new());

    //unpack seed part of pk
    in_rho.copy_from_slice(&pk[KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES..]);

    // H(pw || sid || rho) -> mask_seed_t (R in paper)
    hash_in_lr[..KYBER_SYMBYTES].copy_from_slice(pw);
    hash_in_lr[KYBER_SYMBYTES..2*KYBER_SYMBYTES].copy_from_slice(sid);
    hash_in_lr[2*KYBER_SYMBYTES..].copy_from_slice(&in_rho);
    hash_h(&mut mask_seed_t, &hash_in_lr, 3*KYBER_SYMBYTES);

    //unpack vec part of pk
    polyvec_frombytes(&mut in_t, pk);

    // H'(mask_seed_t) -> mask_t
    utils::gen_vector(&mut mask_t, &mask_seed_t);
    polyvec_add(&mut mask_t, &in_t);
    polyvec_reduce(&mut mask_t);

    //pack vec part of masked pk for hashing
    polyvec_tobytes(icc, &mask_t);

    // G(pw,vecpartpk) -> key
    hash_in_rl[..KYBER_SYMBYTES].copy_from_slice(pw);
    hash_in_rl[KYBER_SYMBYTES..2*KYBER_SYMBYTES].copy_from_slice(sid);
    hash_in_rl[2*KYBER_SYMBYTES..].copy_from_slice(&icc[..KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES]);
    hash_h(&mut key, &hash_in_rl, 2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES);

    ic::ic256_enc(&mut in_rho, &key);

    icc[KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES..].copy_from_slice(&in_rho[..KYBER_SYMBYTES]);

    Ok(())

}


/// Name:  hic_inv
///
/// Description: Computes the half-ideal cipher over a Kyber pk
/// 
/// Results:     - [u8] pk: the output public key (of length KYBER_PUBLICKEYBYTES bytes)
///
/// Arguments:   - [u8] icc: input ciphertext (of length KYBER_PUBLICKEYBYTES bytes)
///              - [u8] pw: input password (of length KYBER_SYMBYTES bytes)
///              - [u8] sid: input sid (of length KYBER_SYMBYTES bytes)
pub fn hic_inv(
    pk: &mut [u8;KYBER_PUBLICKEYBYTES],
    icc: &[u8;KYBER_PUBLICKEYBYTES],
    pw: &[u8;KYBER_SYMBYTES],
    sid: &[u8;KYBER_SYMBYTES]
) -> Result<(),KyberError>
{
    let mut hash_in_lr = [0u8;3*KYBER_SYMBYTES];
    let mut hash_in_rl = [0u8;2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES];
    let mut in_rho = [0u8;KYBER_SYMBYTES];
    let mut key = [0u8;KYBER_SYMBYTES];
    let mut mask_seed_t = [0u8;KYBER_SYMBYTES];
    let (mut in_t,mut mask_t) = (Polyvec::new(), Polyvec::new());

    // G(pw,vecpartpk) -> key
    hash_in_rl[..KYBER_SYMBYTES].copy_from_slice(pw);
    hash_in_rl[KYBER_SYMBYTES..2*KYBER_SYMBYTES].copy_from_slice(sid);
    hash_in_rl[2*KYBER_SYMBYTES..].copy_from_slice(&icc[..KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES]);
    hash_h(&mut key, &hash_in_rl, 2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES);

    // unpack and decrypt seed part of icc
    in_rho[0..32].copy_from_slice(&icc[KYBER_INDCPA_PUBLICKEYBYTES-KYBER_SYMBYTES..]);
    ic::ic256_dec(&mut in_rho, &key);

    // H(pw || rho) -> mask_seed_t
    hash_in_lr[..KYBER_SYMBYTES].copy_from_slice(pw);
    hash_in_lr[KYBER_SYMBYTES..2*KYBER_SYMBYTES].copy_from_slice(sid);
    hash_in_lr[2*KYBER_SYMBYTES..].copy_from_slice(&in_rho);
    hash_h(&mut mask_seed_t, &hash_in_lr, 3*KYBER_SYMBYTES);

    //unpack vec part of pk
    polyvec_frombytes(&mut in_t, icc);

    // H'(mask_seed_t) -> mask_t
    utils::gen_vector(&mut mask_t, &mask_seed_t);
    polyvec_sub(&mut mask_t, &in_t);
    polyvec_reduce(&mut mask_t);

    //pack_pk
    polyvec_tobytes(pk, &mask_t);
    pk[KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES..KYBER_PUBLICKEYBYTES].copy_from_slice(&in_rho[..KYBER_SYMBYTES]);

    Ok(())

}

#[cfg(test)]
mod tests {

    use rand::RngCore;
    use pqc_kyber;
    use super::*;

    #[test]
    fn test_hic() {
        let mut sid = [0u8;KYBER_SSBYTES];
        let mut pw = [0u8;KYBER_SSBYTES];
        let mut sk_a = [0u8;KYBER_SECRETKEYBYTES];
        let mut pk_a = [0u8;KYBER_PUBLICKEYBYTES];
        let mut pk_b = [0u8;KYBER_PUBLICKEYBYTES];
        let mut icc = [0u8;KYBER_PUBLICKEYBYTES];
    
        let mut rng = rand::thread_rng();
    
        rng.fill_bytes(&mut sid);
        rng.fill_bytes(&mut pw);
    
        let keypair = pqc_kyber::keypair(&mut rng).unwrap();
        pk_a.copy_from_slice(&keypair.public);
        sk_a.copy_from_slice(&keypair.secret);
    
        assert_eq!(hic_eval(&mut icc, &pk_a, &pw, &sid), Ok(()));
        assert_eq!(hic_inv(&mut pk_b, &icc, &pw, &sid), Ok(()));
        assert_eq!(pk_a, pk_b);
    }
}