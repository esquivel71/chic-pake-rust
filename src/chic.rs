use crate::hic::hic_inv;
use crate::symmetric::{hash_g,hash_h};
use crate::reference::verify::{cmov,verify};
use crate::params::{KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_SYMBYTES, MSG1_LEN, MSG2_LEN};
use rand_core::{CryptoRng, RngCore};
use crate::{hic,error::*};


/// Name:  init_start
///
/// Description: First stage of initiator
/// 
/// Results:     - [u8] msg1: the outgoing message (of length MSG1_LEN)
///              - [u8] pk: the pk part of the state (of length KYBER_PUBLICKEYBYTES)
///              - [u8] sk: the sk part of the state (of length KYBER_SECRETKEYBYTES)
///
/// Arguments:   - [u8] pw: the input pw (of length KYBER_SYMBYTES)
///              - [u8] sid: the input sid (of length KYBER_SYMBYTES)
///              - _rng: the RNG to be used by keypair
///              - keypair: closure that contains the keypair logic
pub fn init_start<R,F>(
    msg1: &mut [u8;MSG1_LEN],
    pk: &mut [u8;KYBER_PUBLICKEYBYTES],
    sk: &mut [u8;KYBER_SECRETKEYBYTES],
    pw: &[u8;KYBER_SYMBYTES],
    sid: &[u8;KYBER_SYMBYTES],
    _rng: &mut R,
    maybe_keypair: Option<F>
) -> Result<(), PakeError>
where
    R: RngCore + CryptoRng,
    F: FnMut(&mut R) -> ([u8;KYBER_PUBLICKEYBYTES],[u8;KYBER_SECRETKEYBYTES])
{
    match maybe_keypair {
        Some(mut keypair) => {
            let (kyber_pk,kyber_sk) = keypair(_rng);
            pk.copy_from_slice(&kyber_pk);
            sk.copy_from_slice(&kyber_sk);
        }
        None => {
            #[cfg(feature = "default-kyber")] {
                let keys = pqc_kyber::keypair(_rng).unwrap();
                pk.copy_from_slice(&keys.public);
                sk.copy_from_slice(&keys.secret);
            }
            #[cfg(not(feature = "default-kyber"))] {
                return Err(PakeError::InvalidInput);
            }
        }
    }
    
    let _ = hic::hic_eval(msg1, &(*pk), pw, sid);
    Ok(())
}

/// Name:  resp
///
/// Description: First message from initiator
/// 
/// Results:     - [u8] key: the output key (of length KYBER_SYMBYTES)
///              - [u8] msg2: the output message (of length KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES (MSG2_LEN) )
///
/// Arguments:   - [u8] msg1: the input message (of length KYBER_PUBLICKEYBYTES (MSG1_LEN) )
///              - [u8] pw: the pw (of length KYBER_SYMBYTES)
///              - [u8] sid: the input sid (of length KYBER_SYMBYTES)
///              - _rng: the RNG to be used by encapsulate
///              - encapsulate: closure that contains the encapsulation logic
pub fn resp<R,F>(
    key: &mut [u8;KYBER_SYMBYTES],
    msg2: &mut [u8;MSG2_LEN],
    init_tag: &mut [u8;KYBER_SYMBYTES],
    msg1: &[u8;KYBER_PUBLICKEYBYTES],
    pw: &[u8;KYBER_SYMBYTES],
    sid: &[u8;KYBER_SYMBYTES],
    _rng: &mut R,
    maybe_encapsulate: Option<F>
) -> Result<(), PakeError>
where
    R: RngCore + CryptoRng,
    F: FnMut(&[u8;KYBER_PUBLICKEYBYTES],&mut R) -> ([u8;KYBER_CIPHERTEXTBYTES],[u8;KYBER_SYMBYTES])
{
    let mut pk = [0u8;KYBER_PUBLICKEYBYTES];
    let mut keytag = [0u8;2*KYBER_SYMBYTES];
    let mut hashin = [0u8;2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES+1];
    // let mut init_tag = [0u8;KYBER_SYMBYTES];

    let _ = hic_inv(&mut pk, msg1, pw, sid);
    match maybe_encapsulate {
        Some(mut encapsulate) => {
            let (ct, ss) = encapsulate(&(pk), _rng);
            msg2[KYBER_SYMBYTES..].copy_from_slice(&ct);
            hashin[..KYBER_SYMBYTES].copy_from_slice(&ss);
        }
        None => {
            #[cfg(feature = "default-kyber")] {
                let (ct,ss) = pqc_kyber::encapsulate(&pk, _rng).unwrap();
                msg2[KYBER_SYMBYTES..].copy_from_slice(&ct);
                hashin[..KYBER_SYMBYTES].copy_from_slice(&ss);
            }
            #[cfg(not(feature = "default-kyber"))] {
                return Err(PakeError::InvalidInput);
            }
            
        }
    }
    
    // Tag = H(K_s,sid,pk,apk,cph)
    hashin[KYBER_SYMBYTES..2*KYBER_SYMBYTES].copy_from_slice(sid);
    hashin[2*KYBER_SYMBYTES..2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES].copy_from_slice(&pk);
    hashin[2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES..2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES].copy_from_slice(msg1);
    hashin[2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES..2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES].copy_from_slice(&msg2[KYBER_SYMBYTES..KYBER_SYMBYTES+KYBER_CIPHERTEXTBYTES]);
    // Responder to initiator key confirmation tag
    hashin[2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES] = 0;
    hash_g(&mut keytag, &hashin, 2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES+1);
    key[..KYBER_SYMBYTES].copy_from_slice(&keytag[..KYBER_SYMBYTES]);
    msg2[..KYBER_SYMBYTES].copy_from_slice(&keytag[KYBER_SYMBYTES..2*KYBER_SYMBYTES]);

    // Pre calculate initiator to responder key confirmation tag
    let mut to_authenticate = [0u8; 2*KYBER_SYMBYTES];
    to_authenticate[..KYBER_SYMBYTES].copy_from_slice(key);
    to_authenticate[KYBER_SYMBYTES..].copy_from_slice(sid);
    hash_h(init_tag, &to_authenticate, KYBER_SYMBYTES);

    Ok(())
}

/*************************************************
* Name:        initEnd
*
* Description: Last stage of initiator
*
* Results:   key: the output key
*                 (of length KYBER_SYMBYTES)
*            return value: 0 if ok, -1 if not ok
* 
* Arguments: msg2: the input message
*                 (of length MSG2_LEN)
*            msg1: the previously sent message
*                 (of length MSG1_LEN)
*            pk: the pk part of the state
*                 (of length KYBER_PUBLICKEYBYTES)
*            sk: the sk part of the state
*                 (of length KYBER_SECRETKEYBYTES)
*            sid: the input sid
*                 (of length KYBER_SYMBYTES)
* 
**************************************************/

/// Name:  init_end
///
/// Description: Last stage of initiator
/// 
/// Results:     - [u8] key: the output key (of length KYBER_SYMBYTES)
///
/// Arguments:   - [u8] msg2: the input message (of length MSG2_LEN )
/// Arguments:   - [u8] msg1: the previously sent message (of length MSG1_LEN )
///              - [u8] pk: the pk part of the state (of length KYBER_PUBLICKEYBYTES)
///              - [u8] sk: the sk part of the state (of length KYBER_SECRETKEYBYTES)
///              - [u8] sid: the input sid (of length KYBER_SYMBYTES)
///              - decapsulate: closure that contains the decapsulation logic
/// 
/// Return values: 0 if ok, -1 if not ok
pub fn init_end<F>(
    key: &mut [u8;KYBER_SYMBYTES],
    init_tag: &mut [u8; KYBER_SYMBYTES],
    msg2: &[u8;MSG2_LEN],
    msg1: &[u8;MSG1_LEN],
    pk: &[u8;KYBER_PUBLICKEYBYTES],
    sk: &[u8;KYBER_SECRETKEYBYTES],
    sid: &[u8;KYBER_SYMBYTES],
    maybe_decapsulate: Option<F>
) -> Result<u8, PakeError>
where
    F: FnMut(&[u8;KYBER_CIPHERTEXTBYTES],&[u8;KYBER_SECRETKEYBYTES]) -> [u8;KYBER_SYMBYTES]
{
    let mut keytag = [0u8;2*KYBER_SYMBYTES];
    let mut hashin = [0u8;2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES+1];

    let mut ct = [0u8;KYBER_CIPHERTEXTBYTES];
    ct.copy_from_slice(&(*msg2)[KYBER_SYMBYTES..]);

    match maybe_decapsulate {
        Some(mut decapsulate) => {
            let decaps = decapsulate(&ct, sk);
            hashin[..KYBER_SYMBYTES].copy_from_slice(&decaps);
        }
        None => {
            #[cfg(feature = "default-kyber")] {
                let decaps = pqc_kyber::decapsulate(&ct, sk).unwrap();
                hashin[..KYBER_SYMBYTES].copy_from_slice(&decaps);
            }
            #[cfg(not(feature = "default-kyber"))] {
                return Err(PakeError::InvalidInput);
            }
        }
    }

    // Tag = H(K_s,sid,pk,apk,cph)
    hashin[KYBER_SYMBYTES..2*KYBER_SYMBYTES].copy_from_slice(sid);
    hashin[2*KYBER_SYMBYTES..2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES].copy_from_slice(pk);
    hashin[2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES..2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES].copy_from_slice(msg1);
    hashin[2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES..2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES].copy_from_slice(&msg2[KYBER_SYMBYTES..KYBER_SYMBYTES+KYBER_CIPHERTEXTBYTES]);
    // Responder to initiator key confirmation tag
    hashin[2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES] = 0;
    hash_g(&mut keytag, &hashin, 2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES+1);

    // Check tag
    let result = verify(&keytag[KYBER_SYMBYTES..], msg2, KYBER_SYMBYTES);

    // If all works out
    cmov(key, &keytag, KYBER_SYMBYTES, (result&1)^1 as u8);

    // Calculate initiator to responder key confirmation tag
    let mut to_authenticate = [0u8; 2*KYBER_SYMBYTES];
    to_authenticate[..KYBER_SYMBYTES].copy_from_slice(key);
    to_authenticate[KYBER_SYMBYTES..].copy_from_slice(sid);
    hash_h(init_tag, &to_authenticate, KYBER_SYMBYTES);

    Ok(result)
}

#[cfg(test)]
mod tests {

    use rand::{rngs::ThreadRng, RngCore};
    use crate::params::*;
    use super::*;

    #[test]
    fn test_chic_kyber_ref() {
        let mut sid = [0u8;KYBER_SSBYTES];
        let mut pw = [0u8;KYBER_SSBYTES];
        let mut sk = [0u8;KYBER_SECRETKEYBYTES];
        let mut pk = [0u8;KYBER_PUBLICKEYBYTES];
        let mut key_a = [0u8;KYBER_SSBYTES];
        let mut key_b = [0u8;KYBER_SSBYTES];
        let mut msg1 = [0u8;MSG1_LEN];
        let mut msg2 = [0u8;MSG2_LEN];
        let mut init_tag = [0u8;KYBER_SYMBYTES];
        let mut init_tag_2 = [0u8;KYBER_SYMBYTES];
        
        let mut rng = rand::thread_rng();
    
        rng.fill_bytes(&mut pw);
        rng.fill_bytes(&mut sid);

        let keypair_func = | rng: &mut rand::rngs::ThreadRng | {
            let keypair = pqc_kyber::keypair(rng).unwrap();
            let pk = keypair.public;
            let sk = keypair.secret;
            (pk,sk)
        };

        let encapsulate_func= | pk: &[u8;KYBER_PUBLICKEYBYTES], rng: &mut rand::rngs::ThreadRng | {
            let (ct,ss) = pqc_kyber::encapsulate(pk, rng).unwrap();
            (ct,ss)
        };

        let decapsulate_func= | ct: &[u8;KYBER_CIPHERTEXTBYTES], sk: &[u8;KYBER_SECRETKEYBYTES] | {
            let ss = pqc_kyber::decapsulate(ct, sk).unwrap();
            ss
        };

        // msg1 is the encrypted public key Alice sends to Bob
        assert_eq!(init_start(&mut msg1, &mut pk, &mut sk, &pw, &sid, &mut rng, Some(keypair_func)), Ok(()));
        // key_a is the shared secret Bob derived, and msg2 is the ciphertext containing that secret
        assert_eq!(resp(&mut key_a, &mut msg2, &mut init_tag, &msg1, &pw, &sid, &mut rng, Some(encapsulate_func)), Ok(()));
        // last step receives msg2, the ciphertext containing the shared secret, and outputs key_b, the shared secret =key_a
        assert_eq!(init_end(&mut key_b, &mut init_tag_2, &msg2, &msg1, &pk, &sk, &sid, Some(decapsulate_func)), Ok(0));

        assert_eq!(key_a, key_b);

        // Test key confirmation from initiator to responder
        assert_eq!(init_tag,init_tag_2);
    }

    #[test]
    #[cfg(feature = "default-kyber")]
    fn test_chic_default_kyber() {
        let mut sid = [0u8;KYBER_SSBYTES];
        let mut pw = [0u8;KYBER_SSBYTES];
        let mut sk = [0u8;KYBER_SECRETKEYBYTES];
        let mut pk = [0u8;KYBER_PUBLICKEYBYTES];
        let mut dec_pk = [0u8;KYBER_PUBLICKEYBYTES];
        let mut key_a = [0u8;KYBER_SSBYTES];
        let mut key_b = [0u8;KYBER_SSBYTES];
        let mut msg1 = [0u8;MSG1_LEN];
        let mut msg2 = [0u8;MSG2_LEN];
        
        let mut rng = rand::thread_rng();
    
        rng.fill_bytes(&mut pw);
        rng.fill_bytes(&mut sid);


        let keypair_none: Option<fn(&mut ThreadRng) -> ([u8;KYBER_PUBLICKEYBYTES],[u8;KYBER_SECRETKEYBYTES])> = None;
        let encapsulate_none: Option<fn(&[u8;KYBER_PUBLICKEYBYTES], &mut ThreadRng) -> ([u8;KYBER_CIPHERTEXTBYTES],[u8;KYBER_SYMBYTES])> = None;
        let decapsulate_none: Option<fn(&[u8;KYBER_CIPHERTEXTBYTES], &[u8;KYBER_SECRETKEYBYTES]) -> [u8;KYBER_SYMBYTES]> = None;

        // msg1 is the encrypted public key Alice sends to Bob
        assert_eq!(init_start(&mut msg1, &mut pk, &mut sk, &pw, &sid, &mut rng, keypair_none), Ok(()));
        // key_a is the shared secret Bob derived, and msg2 is the ciphertext containing that secret
        assert_eq!(resp(&mut key_a, &mut msg2, &mut dec_pk, &msg1, &pw, &sid, &mut rng, encapsulate_none), Ok(()));
        // last step receives msg2, the ciphertext containing the shared secret, and outputs key_b, the shared secret =key_a
        assert_eq!(init_end(&mut key_b, &mut msg2, &msg1, &pk, &sk, &sid, decapsulate_none), Ok(0));
        
        assert_eq!(key_a, key_b);
    }

}