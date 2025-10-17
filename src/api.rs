use rand_core::{CryptoRng,RngCore};
use crate::{params::*,chic::*,error::*};

pub fn pake_init_start<R,F>(pw: &[u8;KYBER_SYMBYTES], rng: &mut R, mut keypair: F) -> PakeKeyPair
where
    R: CryptoRng + RngCore,
    F: FnMut(&mut R) -> ([u8;KYBER_PUBLICKEYBYTES],[u8;KYBER_SECRETKEYBYTES])
{
    let mut out = [0u8; KYBER_PUBLICKEYBYTES];
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = [0u8;KYBER_SECRETKEYBYTES];
    let mut sid = [0u8;KYBER_SSBYTES];
    rng.fill_bytes(&mut sid);
    init_start(&mut out, &mut pk, &mut sk, pw, &sid, rng, Some(keypair))?;
    let mut enc_pk = [0u8;KYBER_SYMBYTES+KYBER_INDCPA_PUBLICKEYBYTES];
    enc_pk[..KYBER_SYMBYTES].copy_from_slice(&sid);
    enc_pk[KYBER_SYMBYTES..].copy_from_slice(&out);
    Ok((enc_pk,pk,sk))
}


pub fn pake_resp<R,F>(sid: &[u8;KYBER_SYMBYTES], pk: &[u8;KYBER_PUBLICKEYBYTES], pw: &[u8;KYBER_SYMBYTES], rng: &mut R, encapsulate: F) -> PakeEncapsulated
where
    R: CryptoRng + RngCore,
    F: FnMut(&[u8;KYBER_PUBLICKEYBYTES],&mut R) -> ([u8;KYBER_CIPHERTEXTBYTES],[u8;KYBER_SYMBYTES])
{
    if pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(PakeError::InvalidInput);
    }
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
    let mut ss = [0u8; KYBER_SYMBYTES];
    let mut init_tag = [0u8; KYBER_SYMBYTES];
    resp(&mut ss, &mut ct, &mut init_tag, pk, pw, &sid, rng, Some(encapsulate))?;
    Ok((ct, ss, init_tag))
}

pub fn pake_init_end<F>(ct: &[u8;KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES], sid: &[u8; KYBER_SYMBYTES], enc_pk: &[u8;KYBER_PUBLICKEYBYTES], pk: &[u8;KYBER_PUBLICKEYBYTES], sk: &[u8;KYBER_SECRETKEYBYTES], decapsulate: F) -> PakeDecapsulated
where
    F: FnMut(&[u8;KYBER_CIPHERTEXTBYTES],&[u8;KYBER_SECRETKEYBYTES]) -> [u8;KYBER_SYMBYTES]
{
    if pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(PakeError::InvalidInput);
    }
    let mut ss = [0u8; KYBER_SYMBYTES];
    let mut init_tag = [0u8; KYBER_SYMBYTES];
    let result = init_end(&mut ss, &mut init_tag,  ct, enc_pk, pk, sk, &sid, Some(decapsulate))?;
    Ok((ss,init_tag,result))
}

#[cfg(feature = "default-kyber")]
pub fn pake_init_start_ref<R>(pw: &[u8;KYBER_SYMBYTES], rng: &mut R) -> PakeKeyPair
where
    R: CryptoRng + RngCore
{
    let mut out = [0u8; KYBER_PUBLICKEYBYTES];
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = [0u8;KYBER_SECRETKEYBYTES];
    let mut sid = [0u8;KYBER_SSBYTES];
    rng.fill_bytes(&mut sid);

    let keypair_none: Option<fn(&mut R) -> ([u8;KYBER_PUBLICKEYBYTES],[u8;KYBER_SECRETKEYBYTES])> = None;

    init_start(&mut out, &mut pk, &mut sk, pw, &sid, rng, keypair_none)?;
    let mut enc_pk = [0u8;KYBER_SYMBYTES+KYBER_INDCPA_PUBLICKEYBYTES];
    enc_pk[..KYBER_SYMBYTES].copy_from_slice(&sid);
    enc_pk[KYBER_SYMBYTES..].copy_from_slice(&out);
    Ok((enc_pk,pk,sk))
}

#[cfg(feature = "default-kyber")]
pub fn pake_resp_ref<R>(sid: &[u8;KYBER_SYMBYTES], pk: &[u8;KYBER_PUBLICKEYBYTES], pw: &[u8;KYBER_SYMBYTES], rng: &mut R) -> PakeEncapsulated
where
    R: CryptoRng + RngCore,
{
    if pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(PakeError::InvalidInput);
    }
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
    let mut ss = [0u8; KYBER_SYMBYTES];

    let encapsulate_none: Option<fn(&[u8;KYBER_PUBLICKEYBYTES], &mut R) -> ([u8;KYBER_CIPHERTEXTBYTES],[u8;KYBER_SYMBYTES])> = None;

    resp(&mut ss, &mut ct, pk, pw, &sid, rng, encapsulate_none)?;
    Ok((ct, ss))
}

#[cfg(feature = "default-kyber")]
pub fn pake_init_end_ref(ct: &[u8;KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES], sid: &[u8; KYBER_SYMBYTES], enc_pk: &[u8;KYBER_PUBLICKEYBYTES], pk: &[u8;KYBER_PUBLICKEYBYTES], sk: &[u8;KYBER_SECRETKEYBYTES]) -> PakeDecapsulated
{
    
    if pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(PakeError::InvalidInput);
    }
    let mut ct_and_tag = [0u8; KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
    ct_and_tag.copy_from_slice(ct);
    let mut ss = [0u8; KYBER_SYMBYTES];

    let decapsulate_none: Option<fn(&[u8;KYBER_CIPHERTEXTBYTES], &[u8;KYBER_SECRETKEYBYTES]) -> [u8;KYBER_SYMBYTES]> = None;

    let result = init_end(&mut ss, &mut ct_and_tag, enc_pk, pk, sk, &sid, decapsulate_none)?;
    Ok((ss,result))
}