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

fn get_challenge<F: Field, VC: VectorCommitmentScheme<F>>(
    _k: u32,
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
    //TODO: This is not correct, hash should be in [k]
    F::from_random_bytes(&digest).unwrap()
}

// returns a random vector of length n of F where the elements are
// sampled from 0,..k-1
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
        // The parameters are just a fresh commitment key.
        let ck = VC::setup(rng, num_lotteries);
        ck.map(|ck| Self::Parameters {
            ck,
            num_lotteries,
            k,
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

    fn participate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Option<Self::Ticket> {
        // get a challenge
        let x = get_challenge(par.k, pk, pid, i, lseed);
        // we win if x = v_i
        if i as usize > sk.v.len() || sk.v[i as usize] != x {
            return None;
        }
        // if we win, we can get a winning ticket
        // by opening our commitment
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
            xs.push(get_challenge(par.k, &pks[j], pids[j], i, lseed));
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
            xs.push(get_challenge(par.k, &pks[j], pids[j], i, lseed));
            coms.push(&pks[j].com);
        }

        // verify all commitments
        for j in 0..l {
            if !VC::verify_commitment(&par.ck, &pks[j].com) {
                return false;
            }
        }

        // verify the aggregate opening
        VC::verify(&par.ck, i, &xs, &coms, &ticket.opening)
    }
}
