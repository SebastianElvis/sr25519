extern crate schnorrkel;
#[macro_use]
extern crate hex_literal;

use schnorrkel::context::signing_context;
use schnorrkel::vrf::{VRFPreOut, VRFProof};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey, Signature};

pub type SK = SecretKey;
pub type PK = PublicKey;

/// SecretKey helper
fn create_sk(sk_bytes: &[u8]) -> SK {
    match SK::from_bytes(sk_bytes) {
        Ok(sk) => return sk,
        Err(_) => panic!("Provided private key is invalid."),
    }
}

/// PublicKey helper
fn create_pk(pk_bytes: &[u8]) -> PK {
    match PK::from_bytes(pk_bytes) {
        Ok(pk) => return pk,
        Err(_) => panic!("Provided public key is invalid."),
    }
}

pub fn create_keypair(seed: &[u8]) -> (SK, PK) {
    match MiniSecretKey::from_bytes(seed) {
        Ok(mini) => {
            let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
            (keypair.secret.clone(), keypair.public.clone())
        }
        Err(_) => panic!("Provided seed is invalid."),
    }
}

pub fn sign(sk: &SK, message: &[u8]) -> Vec<u8> {
    let context = b"";
    let pk = sk.to_public();
    sk.sign_simple(context, message, &pk).to_bytes().to_vec()
}

pub fn verify(pk: &PK, message: &[u8], signature: &[u8]) -> bool {
    let context = b"";
    let signature = match Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    pk.verify_simple(context, message, &signature).is_ok()
}

pub fn vrf_eval(sk: &SK, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let context = b"";
    let ctx = signing_context(context);
    let keypair = sk.clone().to_keypair();
    let (inout, proof_struct, _) = keypair.vrf_sign(ctx.bytes(message));
    let out = inout.to_preout().to_bytes().to_vec();
    let proof = proof_struct.to_bytes().to_vec();
    (out, proof)
}

pub fn vrf_verify(pk: &PK, message: &[u8], out: &[u8], proof: &[u8]) -> bool {
    let context = b"";
    let ctx = signing_context(context);
    let proof_struct = match VRFProof::from_bytes(proof) {
        Ok(proof_struct) => proof_struct,
        Err(_) => return false,
    };
    let out_struct = match VRFPreOut::from_bytes(out) {
        Ok(out_struct) => out_struct,
        Err(_) => return false,
    };
    match pk.vrf_verify(ctx.bytes(message), &out_struct, &proof_struct) {
        Ok(_) => return true,
        Err(_) => return false,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use hex_literal::hex;
    use schnorrkel::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

    fn generate_random_seed() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }

    #[test]
    fn can_create_keypair() {
        let seed = generate_random_seed();
        let (sk, pk) = create_keypair(seed.as_slice());

        assert!(sk.to_bytes().len() == SECRET_KEY_LENGTH);
        assert!(pk.to_bytes().len() == PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn can_create_correct_keypair() {
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
        let (sk, pk) = create_keypair(&seed);

        assert_eq!(pk.to_bytes(), expected);
    }

    #[test]
    fn can_sign_message() {
        let seed = generate_random_seed();
        let (sk, pk) = create_keypair(seed.as_slice());
        let message = b"this is a message";
        let signature = sign(&sk, message);

        assert!(signature.len() == SIGNATURE_LENGTH);
    }

    #[test]
    fn can_verify_message() {
        let seed = generate_random_seed();
        let (sk, pk) = create_keypair(seed.as_slice());
        let message = b"this is a message";
        let signature = sign(&sk, message);

        assert!(verify(&pk, message, &signature[..]));
    }

    #[test]
    fn can_vrf_verify() {
        let seed = generate_random_seed();
        let (sk, pk) = create_keypair(seed.as_slice());
        let message = b"this is a message";
        let (vrf_out, vrf_proof) = vrf_eval(&sk, message);

        assert!(vrf_verify(&pk, message, &vrf_out, &vrf_proof));
    }
}
