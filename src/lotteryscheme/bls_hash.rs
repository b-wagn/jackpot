use std::ops::Mul;

use super::LotteryScheme;
use ark_bls12_381::g1::Config as G1Config;
use ark_bls12_381::Bls12_381;
use ark_ec::hashing::HashToCurve;
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::Pairing,
    CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, Zero};
use sha2::Digest;
use sha2::Sha256;

/// BLS+Hash lottery scheme
pub struct BLSHash;

/// See https://github.com/ethereum/bls12-381-tests
const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// some helper functions and types
type G1 = <Bls12_381 as Pairing>::G1;
type G2 = <Bls12_381 as Pairing>::G2;
type G1Affine = <Bls12_381 as Pairing>::G1Affine;
type G2Affine = <Bls12_381 as Pairing>::G2Affine;
type F = <Bls12_381 as Pairing>::ScalarField;

pub struct BLSParameters {
    /// generator for G2
    g2: G2Affine,
    /// log (base 2) of k, where k is
    /// inverse of winning probability
    log_k: u32,
}

/// predicate to check if a signature is "winning"
/// Recall: A party wins if its signature is valid and winning
fn winning_predicate(log_k: u32, sig: &G1Affine) -> bool {
    // We hash the signature and check if
    // the first log k bits of it are zero
    let mut hasher = Sha256::new_with_prefix("BLS-HASH-PRED//".as_bytes());
    let mut sig_ser = Vec::new();
    sig.serialize_compressed(&mut sig_ser)
        .expect("Failed to serialize signature in winning_predicate.");
    hasher.update(&sig_ser);
    let digest = hasher.finalize();

    // check that first 8*floor(log_k/8) bits are zero
    assert!(log_k <= 32 * 8);
    let zerobytes = (log_k >> 3) as usize;
    for i in 0..zerobytes {
        if digest[i] != 0x00 {
            return false;
        }
    }
    // check that remaining log_k modulo 8 bits are zero
    let nextbyte = digest[zerobytes];
    let expected = log_k & 0x07;
    let mask = (1 << expected) - 1;
    if (nextbyte & mask) != 0 {
        return false;
    }
    true
}

/// hash a message into group G1
fn hash_to_group(mes: &[u8; 40]) -> G1Affine {
    let hasher =
        MapToCurveBasedHasher::<G1, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>::new(DOMAIN)
            .unwrap();
    hasher.hash(mes).unwrap()
}

/// computes a BLS signature for the given message
fn bls_sign(sk: &F, mes: &[u8; 40]) -> G1Affine {
    // signature is Hash(m)^sk
    let h = hash_to_group(mes);
    h.mul(sk).into_affine()
}

/// verifies a BLS signature
fn bls_ver(g2: &G2Affine, pk: &G2Affine, sig: &G1Affine, mes: &[u8; 40]) -> bool {
    // we let h = H(m)
    let h = hash_to_group(mes);
    // check e(sig, g2) = e(h,pk)
    let lhs = Bls12_381::pairing(sig, g2);
    let rhs = Bls12_381::pairing(h, pk);
    lhs == rhs
}

/// verifies a bunch of BLS signatures for the same message
fn _bls_batch_ver(pks: &[G2Affine], sigs: &[G1Affine], mes: &[u8; 40]) -> bool {
    if pks.len() != sigs.len() {
        return false;
    }
    if pks.len() < 1 {
        return false;
    }
    // we let h = H(m)
    let h = hash_to_group(mes);
    // a single verification is given by equation
    // e(sig_i, g2) = e(h,pk_i)
    // so we batch them together to
    // e(aggsig, g2) = e(h, aggpk)
    // for aggsig = prod_i sig_i^{chi^{i-1}}
    // and aggpk  = prod_i  pk_i^{chi^{i-1}}
    // where chi is derived from the sigs
    let chi = F::zero(); // TODO
    todo!();
}

/// function to assemble the message to sign
/// from a pid, lseed, and lottery number i
fn assemble_message(i: u32, lseed: &[u8; 32], pid: u32) -> [u8; 40] {
    let ibytes = i.to_le_bytes();
    let pidbytes = pid.to_le_bytes();
    let mut mes = [0; 40];
    for j in 0..4 {
        mes[j] = ibytes[j];
    }
    for j in 0..4 {
        mes[4 + j] = pidbytes[j];
    }
    for j in 0..32 {
        mes[8 + j] = lseed[j];
    }
    mes
}

impl LotteryScheme for BLSHash {
    type Parameters = BLSParameters;
    type PublicKey = G2Affine;
    type SecretKey = F;
    type Ticket = G1Affine;
    type LotterySeed = [u8; 32];

    fn setup<R: rand::Rng>(rng: &mut R, _num_lotteries: usize, k: u32) -> Option<Self::Parameters> {
        // sample generator g2
        let g2 = G2::rand(rng);
        if g2.is_zero() {
            return None;
        }
        let g2 = g2.into_affine();
        let log_k = u32::BITS - k.leading_zeros() - 1;
        if 1 << log_k != k || log_k > 256 {
            return None;
        }
        Some(BLSParameters { g2, log_k })
    }

    fn gen<R: rand::Rng>(
        rng: &mut R,
        par: &Self::Parameters,
    ) -> (Self::PublicKey, Self::SecretKey) {
        // key for the lottery is just a BLS key
        let sk = F::rand(rng);
        let pk = par.g2.mul(sk).into_affine();
        (pk, sk)
    }

    fn verify_key(_par: &Self::Parameters, _pk: &Self::PublicKey) -> bool {
        // any key is valid for this scheme
        true
    }

    fn participate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        _pk: &Self::PublicKey,
    ) -> Option<Self::Ticket> {
        // Compute a signature of (lseed,pid,i)
        let mes = assemble_message(i, lseed, pid);
        let sig = bls_sign(sk, &mes);
        // check if it is winning. if it is:
        // output the signature as the ticket
        if !winning_predicate(par.log_k, &sig) {
            return None;
        }
        Some(sig)
    }

    /// Aggregation is not supported
    fn aggregate(
        _par: &Self::Parameters,
        _i: u32,
        _lseed: &Self::LotterySeed,
        _pids: &Vec<u32>,
        _pks: &Vec<Self::PublicKey>,
        _tickets: &Vec<Self::Ticket>,
    ) -> Option<Self::Ticket> {
        None
    }

    fn verify(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pids: &Vec<u32>,
        pks: &Vec<Self::PublicKey>,
        ticket: &Self::Ticket,
    ) -> bool {
        if pids.len() != pks.len() {
            return false;
        }
        if pids.len() != 1 {
            return false;
        }
        // verify signature
        let mes = assemble_message(i, lseed, pids[0]);
        if !bls_ver(&par.g2, &pks[0], &ticket, &mes) {
            return false;
        }
        // verify that it is winning
        if !winning_predicate(par.log_k, &ticket) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::lotteryscheme::{bls_hash::bls_ver, LotteryScheme};

    use super::{bls_sign, BLSHash};

    /// test that an honest BLS signature verifies
    #[test]
    fn test_bls_sign() {
        let mut rng = ark_std::rand::thread_rng();
        let runs = 10;

        for _ in 0..runs {
            // generate parameters and keys
            let par = BLSHash::setup(&mut rng, 1024, 1024).unwrap();
            let (pk, sk) = BLSHash::gen(&mut rng, &par);
            // sign a message
            let mes = [0x08; 40];
            let sig = bls_sign(&sk, &mes);
            // assert that it verifies
            assert!(bls_ver(&par.g2, &pk, &sig, &mes));
        }
    }
}
