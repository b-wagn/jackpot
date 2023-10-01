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
