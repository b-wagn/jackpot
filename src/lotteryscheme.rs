use std::vec;

use ark_std::rand::Rng;

/// This module contains the folklore BLS+Hash
/// lottery scheme. That is, one wins if H(sig) < T
pub mod bls_hash;
/// This module contains Jack, the lottery scheme
/// based on the simulation-extractable KZG variant
/// instantiated using curve Bls12_381
pub mod jack;
/// This module contains a generic lottery scheme
/// based on a given vector commitment scheme
pub mod vcbased;

/// A trait that models a lottery scheme
pub trait LotteryScheme {
    type Parameters;
    type PublicKey;
    type SecretKey;
    type Ticket;
    type LotterySeed;

    /// Set up system parameters
    /// for T lotteries with winning probability 1/k
    fn setup<R: Rng>(rng: &mut R, num_lotteries: usize, k: u32) -> Option<Self::Parameters>;

    /// Generate keys for a user
    fn gen<R: Rng>(rng: &mut R, par: &Self::Parameters) -> (Self::PublicKey, Self::SecretKey);

    /// Verify the well-formedness of a public key
    fn verify_key(par: &Self::Parameters, pk: &Self::PublicKey) -> bool;

    /// Sample a lottery seed for the ith lottery.
    /// In practice, this should most likely be
    /// implemented by a randomness beacon
    fn sample_seed<R: Rng>(rng: &mut R, par: &Self::Parameters, i: u32) -> Self::LotterySeed;

    /// Participant with identifier pid, secret key sk, and public key pk
    /// participates in the ith lottery wiht seed lseed.
    /// This algorithm outputs true if the player won, and false otherwise
    fn participate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> bool;

    /// Participant with identifier pid, secret key sk, and public key pk
    /// participates in the ith lottery with seed lseed.
    /// This algorithm generates a (winning) ticket if the participate won.
    /// Otherwise, it may output None, or a non-winning ticket.
    fn get_ticket(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pid: u32,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Option<Self::Ticket>;

    /// Aggregate tickets tickets[j] of users
    /// with identifiers pids[j] and public keys pks[j] for the ith lottery
    fn aggregate(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pids: &Vec<u32>,
        pks: &Vec<Self::PublicKey>,
        tickets: &Vec<Self::Ticket>,
    ) -> Option<Self::Ticket>;

    /// Verify ticket for the ith lottery with lottery seed lseed
    /// For users with identifiers pids[j] and public keys pks[j]
    fn verify(
        par: &Self::Parameters,
        i: u32,
        lseed: &Self::LotterySeed,
        pids: &Vec<u32>,
        pks: &Vec<Self::PublicKey>,
        ticket: &Self::Ticket,
    ) -> bool;
}

// Test functions for this trait, which can
// be used by implementors of this trait

/// test that if we generate keys honestly, they verify
fn _lottery_test_key_verify<L: LotteryScheme>() {
    let mut rng = ark_std::rand::thread_rng();
    let runs = 10;

    for _ in 0..runs {
        // set up parameters for a lottery
        // for which everyone wins with probability 1
        let num_lotteries = 14;
        let k = 512;
        let par = L::setup(&mut rng, num_lotteries, k).unwrap();
        // generate a key pair
        let (pk, _sk) = L::gen(&mut rng, &par);
        // assert that the pk verifies
        assert!(L::verify_key(&par, &pk));
    }
}

/// test that if we set winning probability to 1/k = 1/1 = 1,
/// then every ticket is winning
fn _lottery_test_always_winning<L: LotteryScheme>() {
    let mut rng = ark_std::rand::thread_rng();
    let runs = 5;

    for _ in 0..runs {
        // set up parameters for a lottery
        // for which everyone wins with probability 1
        let num_lotteries = 14;
        let k = 1;
        let par = L::setup(&mut rng, num_lotteries, k).unwrap();
        // generate key pairs for two users
        let (pk0, sk0) = L::gen(&mut rng, &par);
        let (pk1, sk1) = L::gen(&mut rng, &par);
        let sks = vec![sk0, sk1];
        let pks = vec![pk0, pk1];
        let pids = vec![0, 1];
        // do the lotteries
        for i in 0..num_lotteries {
            // participate should output true
            // for any lottery seed, as both users win with prob 1
            let lseed = L::sample_seed(&mut rng, &par, i as u32);
            assert!(L::participate(
                &par, i as u32, &lseed, pids[0], &sks[0], &pks[0]
            ));
            assert!(L::participate(
                &par, i as u32, &lseed, pids[1], &sks[1], &pks[1]
            ));
            // now that both won, we let them generate their tickets
            let ticket1 = L::get_ticket(&par, i as u32, &lseed, pids[0], &sks[0], &pks[0]);
            let ticket2 = L::get_ticket(&par, i as u32, &lseed, pids[1], &sks[1], &pks[1]);
            assert!(ticket1.is_some());
            assert!(ticket2.is_some());
            let ticket1 = ticket1.unwrap();
            let ticket2 = ticket2.unwrap();
            // we aggregate the tickets
            let ticket = L::aggregate(&par, i as u32, &lseed, &pids, &pks, &vec![ticket1, ticket2]);
            assert!(ticket.is_some());
            let ticket = ticket.unwrap();
            // the aggregated ticket should verify
            assert!(L::verify(&par, i as u32, &lseed, &pids, &pks, &ticket));
        }
    }
}
