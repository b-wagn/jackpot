use std::ops::Mul;

use super::LotteryScheme;
use ark_bls12_381::g1::Config as G1Config;
use ark_bls12_381::Bls12_381;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::CanonicalSerialize;
use ark_std::{One, UniformRand, Zero};
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
type G1Prepared = <Bls12_381 as Pairing>::G1Prepared;
type G2Prepared = <Bls12_381 as Pairing>::G2Prepared;
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
fn hash_to_group(mes: &[u8; 36]) -> G1Affine {
    let hasher =
        MapToCurveBasedHasher::<G1, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>::new(DOMAIN)
            .unwrap();
    hasher.hash(mes).unwrap()
}

/// computes a BLS signature for the given message
fn bls_sign(sk: &F, mes: &[u8; 36]) -> G1Affine {
    // signature is Hash(m)^sk
    let h = hash_to_group(mes);
    h.mul(sk).into_affine()
}

/// verifies a BLS signature
fn bls_ver(g2: &G2Affine, pk: &G2, sig: &G1, mes: &[u8; 36]) -> bool {
    // we let h = H(m)
    let h = hash_to_group(mes);
    // check e(sig, g2) = e(h,pk)
    // Naive implementation would do:
    //  let lhs = Bls12_381::pairing(sig, g2);
    //  let rhs = Bls12_381::pairing(h, pk);
    //  lhs == rhs
    // But we can do it faster:
    let left = vec![G1Prepared::from(sig), G1Prepared::from(-h)];
    let right = vec![G2Prepared::from(g2), G2Prepared::from(pk)];
    let q = Bls12_381::multi_pairing(left, right);
    q.is_zero()
}

/// verifies a bunch of BLS signatures for the same message
fn bls_batch_ver(g2: &G2Affine, pks: &[G2Affine], sigs: &[G1Affine], mes: &[u8; 36]) -> bool {
    if pks.len() != sigs.len() {
        return false;
    }
    if pks.len() < 1 {
        return false;
    }
    let le = pks.len();
    // we let h = H(m)
    // a single verification is given by equation
    // e(sig_i, g2) = e(h,pk_i)
    // so we batch them together to
    // e(aggsig, g2) = e(h, aggpk)
    // for aggsig = prod_i sig_i^{chi^{i-1}}
    // and aggpk  = prod_i  pk_i^{chi^{i-1}}
    // where chi is random and we use MSMs
    let mut rng = ark_std::rand::thread_rng();
    let chi = F::rand(&mut rng);
    let mut chi_powers = Vec::with_capacity(le);
    chi_powers.push(F::one());
    for j in 1..le {
        chi_powers.push(chi_powers[j - 1] * chi);
    }
    let aggsig = <G1 as VariableBaseMSM>::msm(&sigs, &chi_powers).unwrap();
    let aggpk = <G2 as VariableBaseMSM>::msm(&pks, &chi_powers).unwrap();

    bls_ver(g2, &aggpk, &aggsig, mes)
}

/// function to assemble the message to sign
/// from lseed, and lottery number i.
/// Note: We do not add pid as part of the message
/// to make batch verification possible. However,
/// this means that two parties with the same public
/// key will always win either both or not.
/// A real system should handle this case differently
fn assemble_message(i: u32, lseed: &[u8; 32]) -> [u8; 36] {
    let ibytes = i.to_le_bytes();
    let mut mes = [0; 36];
    for j in 0..4 {
        mes[j] = ibytes[j];
    }
    for j in 0..32 {
        mes[4 + j] = lseed[j];
    }
    mes
}

impl LotteryScheme for BLSHash {
    type Parameters = BLSParameters;
    type PublicKey = G2Affine;
    type SecretKey = F;
    type Ticket = Vec<G1Affine>; // trivial aggregation
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

    fn sample_seed<R: rand::Rng>(
        rng: &mut R,
        _par: &Self::Parameters,
        _i: u32,
    ) -> Self::LotterySeed {
        let mut res = [0x00; 32];
        rng.fill_bytes(&mut res);
        res
    }

    fn participate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> bool {
        // compute the ticket. This does not panic.
        let opt_ticket = Self::get_ticket(par, i, lseed, pid, sk, pk);
        let sig = opt_ticket.unwrap()[0];
        // check if it is winning.
        winning_predicate(par.log_k, &sig)
    }

    fn get_ticket(
        _par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        _pid: u32,
        sk: &Self::SecretKey,
        _pk: &Self::PublicKey,
    ) -> Option<Self::Ticket> {
        // Compute a signature of (lseed,pid,i)
        let mes = assemble_message(i, lseed);
        let sig = bls_sign(sk, &mes);
        // The signature is the ticket
        Some(vec![sig])
    }

    /// Aggregation is not supported
    fn aggregate(
        _par: &Self::Parameters,
        _i: u32,
        _lseed: &Self::LotterySeed,
        _pids: &Vec<u32>,
        _pks: &Vec<Self::PublicKey>,
        tickets: &Vec<Self::Ticket>,
    ) -> Option<Self::Ticket> {
        // Trivial aggregation:
        // Tickets are just concatenated
        Some(tickets.concat())
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
        if pids.len() != ticket.len() {
            return false;
        }
        if pids.len() < 1 {
            return false;
        }
        // verify all signatures
        let mes = assemble_message(i, lseed);
        if !bls_batch_ver(&par.g2, pks, ticket, &mes) {
            return false;
        }
        // verify that all signatures are winning
        for sig in ticket {
            if !winning_predicate(par.log_k, &sig) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, AffineRepr};
    use ark_std::UniformRand;

    use crate::lotteryscheme::{
        bls_hash::{bls_batch_ver, bls_ver},
        LotteryScheme, _lottery_test_always_winning, _lottery_test_key_verify,
    };

    use super::{bls_sign, BLSHash};

    type G1 = <Bls12_381 as Pairing>::G1;

    /// test that an honest BLS signature verifies
    #[test]
    fn test_bls_sign_and_ver() {
        let mut rng = ark_std::rand::thread_rng();
        let runs = 10;

        for _ in 0..runs {
            // generate parameters and keys
            let par = BLSHash::setup(&mut rng, 1024, 1024).unwrap();
            let (pk, sk) = BLSHash::gen(&mut rng, &par);
            // sign a message
            let mes = [0x08; 36];
            let sig = bls_sign(&sk, &mes);
            //let sig = <Bls12<ark_bls12_381::Config> as Pairing>::G1Affine::rand(&mut rng);
            // assert that it verifies
            assert!(bls_ver(&par.g2, &pk.into_group(), &sig.into_group(), &mes));
            // random element should not verify
            let sig = G1::rand(&mut rng);
            assert!(!bls_ver(&par.g2, &pk.into_group(), &sig, &mes));
        }
    }

    /// test that a bunch of honest BLS signatures batch verify
    #[test]
    fn test_bls_sign_and_batch_ver() {
        let mut rng = ark_std::rand::thread_rng();
        let runs = 5;
        let numkeys = 20;
        for _ in 0..runs {
            // generate parameters and some keys
            let par = BLSHash::setup(&mut rng, 1024, 1024).unwrap();
            let mut pks = Vec::new();
            let mut sks = Vec::new();
            for _ in 0..numkeys {
                let (pk, sk) = BLSHash::gen(&mut rng, &par);
                pks.push(pk);
                sks.push(sk);
            }

            // sign a message with all keys
            let mes = [0x08; 36];
            let mut sigs = Vec::new();
            for j in 0..numkeys {
                let sig = bls_sign(&sks[j], &mes);
                sigs.push(sig);
            }
            // assert that they batch verify
            assert!(bls_batch_ver(&par.g2, &pks, &sigs, &mes));
        }
    }

    #[test]
    fn blshash_lottery_test_key_verify() {
        _lottery_test_key_verify::<BLSHash>();
    }

    #[test]
    fn blshash_lottery_test_always_winning() {
        _lottery_test_always_winning::<BLSHash>();
    }
}
