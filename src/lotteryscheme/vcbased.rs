use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;

use super::LotteryScheme;
use crate::vectorcommitment::VectorCommitmentScheme;

/*
 * Implementation of a lottery scheme from
 * a vector commitment scheme
 */

pub struct VCLotteryScheme<F: Field, VC: VectorCommitmentScheme<F>> {
    _f: PhantomData<F>,
    _vc: PhantomData<VC>,
}
pub struct Parameters<F: Field, VC: VectorCommitmentScheme<F>> {
    pub ck: VC::CommitmentKey,
    pub num_lotteries: usize,
    pub k: u32,
    pub log_k: u32,
}
pub struct PublicKey<F: Field, VC: VectorCommitmentScheme<F>> {
    pub com: VC::Commitment,
}
pub struct SecretKey<F: Field, VC: VectorCommitmentScheme<F>> {
    pub v: Vec<F>,
    pub state: VC::State,
}
pub struct Ticket<F: Field, VC: VectorCommitmentScheme<F>> {
    pub opening: VC::Opening,
}
pub type LotterySeed = [u8; 32];

#[inline]
fn get_challenge<F: Field, VC: VectorCommitmentScheme<F>>(
    log_k: u32,
    pk: &PublicKey<F, VC>,
    pid: u32,
    i: u32,
    lseed: &LotterySeed,
) -> F {
    // x = H(pk,pid,i,lseed)
    let mut hasher = Sha256::new_with_prefix("Chall//".as_bytes());
    let mut pk_ser = Vec::new();
    pk.com
        .serialize_uncompressed(&mut pk_ser)
        .expect("Failed to serialize public key in get_challenge");
    hasher.update(pk_ser);
    hasher.update(pid.to_be_bytes());
    hasher.update(i.to_be_bytes());
    hasher.update(lseed);

    let digest = hasher.finalize();
    // we take the first log_k bits and interpret as an integer
    // for that, first find out how many bytes we use entirely
    assert!(log_k <= 32 * 8);
    let num_fullbytes = (log_k >> 3) as usize;
    let mut hashbytes: Vec<u8> = vec![0x00; num_fullbytes + 1];
    for j in 0..num_fullbytes {
        hashbytes[j] = digest[j];
    }
    // for the final byte we only need a part of it
    let nextbyte = digest[num_fullbytes];
    let expected = log_k & 0x07;
    let mask = (1 << expected) - 1;
    hashbytes[num_fullbytes] = nextbyte & mask;
    // interpret as field element
    F::from_random_bytes(&hashbytes).unwrap()
}

// returns a random vector of length n of F where the elements are
// sampled from 0,..k-1
#[inline]
fn get_random_field_vec<R: rand::Rng, F: Field>(rng: &mut R, k: u32, n: usize) -> Vec<F> {
    (0..n)
        .map(|_| {
            let r = rng.gen_range(0..k);
            F::from(r)
        })
        .collect()
}

impl<F: Field, VC: VectorCommitmentScheme<F>> LotteryScheme for VCLotteryScheme<F, VC> {
    type Parameters = Parameters<F, VC>;
    type PublicKey = PublicKey<F, VC>;
    type SecretKey = SecretKey<F, VC>;
    type Ticket = Ticket<F, VC>;
    type LotterySeed = LotterySeed;

    fn setup<R: rand::Rng>(rng: &mut R, num_lotteries: usize, k: u32) -> Option<Self::Parameters> {
        // we abort for insane values of k
        // namely, if log_2 k > 256 or k is not power of two
        let log_k = u32::BITS - k.leading_zeros() - 1;
        if 1 << log_k != k || log_k > 256 {
            return None;
        }

        // The parameters are just a fresh commitment key.
        let ck = VC::setup(rng, num_lotteries);
        ck.map(|ck| Self::Parameters {
            ck,
            num_lotteries,
            k,
            log_k,
        })
    }

    fn gen<R: rand::Rng>(
        rng: &mut R,
        par: &Self::Parameters,
    ) -> (Self::PublicKey, Self::SecretKey) {
        // A public key is a commitment to a random vector
        // The secret key is the random vector over a range of size k and the commitment state

        let v = get_random_field_vec(rng, par.k, par.num_lotteries);
        let (com, state) = VC::commit(rng, &par.ck, &v);
        let pk = Self::PublicKey { com };
        let sk = Self::SecretKey { v, state };
        (pk, sk)
    }

    fn verify_key(par: &Self::Parameters, pk: &Self::PublicKey) -> bool {
        VC::verify_commitment(&par.ck, &pk.com)
    }

    fn participate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> bool {
        // get a challenge
        let x = get_challenge(par.log_k, pk, pid, i, lseed);
        // we win if x = v_i
        i as usize <= sk.v.len() && sk.v[i as usize] != x
    }

    fn get_ticket(
        par: &Self::Parameters,
        i: u32,
        _lseed: &Self::LotterySeed,
        _pid: u32,
        sk: &Self::SecretKey,
        _pk: &Self::PublicKey,
    ) -> Option<Self::Ticket> {
        // a ticket is just an opening of our commitment
        let op_tau = VC::open(&par.ck, &sk.state, i);
        op_tau.map(|tau| Ticket { opening: tau })
    }

    fn aggregate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pids: &Vec<u32>,
        pks: &Vec<Self::PublicKey>,
        tickets: &Vec<Self::Ticket>,
    ) -> Option<Self::Ticket> {
        if pids.len() != pks.len() || pids.len() != tickets.len() {
            return None;
        }
        let l = pids.len();

        // compute the challenge for each party
        // and collect commitments and openings for each party
        let mut xs = Vec::new();
        let mut coms = Vec::new();
        let mut openings = Vec::new();
        for j in 0..l {
            xs.push(get_challenge(par.log_k, &pks[j], pids[j], i, lseed));
            coms.push(&pks[j].com);
            openings.push(&tickets[j].opening);
        }

        // let the vector commitment aggregate
        let agg_op = VC::aggregate(&par.ck, i, &xs, &coms, &openings);
        agg_op.map(|tau| Ticket { opening: tau })
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
        let l = pids.len();

        // compute the challenge for each party
        // and collect commitments for each party
        let mut xs = Vec::new();
        let mut coms = Vec::new();
        for j in 0..l {
            xs.push(get_challenge(par.log_k, &pks[j], pids[j], i, lseed));
            coms.push(&pks[j].com);
        }

        // verify the aggregate opening
        VC::verify(&par.ck, i, &xs, &coms, &ticket.opening)
    }
}
