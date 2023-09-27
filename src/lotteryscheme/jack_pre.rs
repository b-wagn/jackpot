use crate::vectorcommitment::kzg::precompute_openings;

use super::{jack::Jack, LotteryScheme};

pub struct JackPre;

/*
 JackPre is the same as Jack. The only difference is in key gen: We preprocess the secret key.
*/
impl LotteryScheme for JackPre {
    type Parameters = <Jack as LotteryScheme>::Parameters;
    type PublicKey = <Jack as LotteryScheme>::PublicKey;
    type SecretKey = <Jack as LotteryScheme>::SecretKey;
    type Ticket = <Jack as LotteryScheme>::Ticket;
    type LotterySeed = <Jack as LotteryScheme>::LotterySeed;

    fn setup<R: rand::Rng>(rng: &mut R, num_lotteries: usize, k: u32) -> Option<Self::Parameters> {
        <Jack as LotteryScheme>::setup(rng, num_lotteries, k)
    }

    fn gen<R: rand::Rng>(
        rng: &mut R,
        par: &Self::Parameters,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let (pk, mut sk) = <Jack as LotteryScheme>::gen(rng, par);
        precompute_openings(&par.ck, &mut sk.state);
        (pk, sk)
    }

    fn verify_key(par: &Self::Parameters, pk: &Self::PublicKey) -> bool {
        <Jack as LotteryScheme>::verify_key(par, pk)
    }

    fn participate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Option<Self::Ticket> {
        <Jack as LotteryScheme>::participate(par, i, lseed, pid, sk, pk)
    }

    fn aggregate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pids: &Vec<u32>,
        pks: &Vec<Self::PublicKey>,
        tickets: &Vec<Self::Ticket>,
    ) -> Option<Self::Ticket> {
        <Jack as LotteryScheme>::aggregate(par, i, lseed, pids, pks, tickets)
    }

    fn verify(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pids: &Vec<u32>,
        pks: &Vec<Self::PublicKey>,
        ticket: &Self::Ticket,
    ) -> bool {
        <Jack as LotteryScheme>::verify(par, i, lseed, pids, pks, ticket)
    }
}
