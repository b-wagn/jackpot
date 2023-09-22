use ark_std::rand::Rng;

pub mod vcbased;

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

    /// Participant with identifier pid participates in the ith lottery.
    fn participate(
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
