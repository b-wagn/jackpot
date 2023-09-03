use std::ops::{Add, Mul};

use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

pub trait VectorCommitmentScheme<F: Field> {
    type CommitmentKey;
    type Commitment: Mul<F, Output = Self::Commitment> + Add<Output=Self::Commitment> + CanonicalSerialize;
    type Opening: Mul<F, Output = Self::Opening> + Add<Output=Self::Opening>;
    type State;

    /* Set up commitment key. Ideally, this should be implemented by a distributed protocol */
    fn setup<R: Rng>(rng: &mut R, message_length: usize) -> Self::CommitmentKey;

    /* Commit to a vector m over the field */
    fn commit<R: Rng>(
        rng: &mut R,
        ck: &Self::CommitmentKey,
        m: &Vec<F>,
    ) -> (Self::Commitment, Self::State);

    /* Verify that a given commitment com is well-formed */
    fn verify_commitment(ck: &Self::CommitmentKey, com: &Self::Commitment) -> bool;

    /* Open a commitment at position i, using the state output by function commit */
    fn open(st: &Self::State, i: usize) -> Option<Self::Opening>;
    
    /* Aggregate some openings at the same position i         */
    /* Assuming that openings[j] is an opening for commitment */
    /* coms[j] at position i to value mis[j]                  */
    fn aggregate(
        ck: &Self::CommitmentKey,
        i: u32,
        mis: &Vec<F>,
        coms: &Vec<Self::Commitment>,
        openings: &Vec<Self::Opening>,
    ) -> Option<Self::Opening>;

    /* Verify an (aggregated) opening    */
    /* The opening is meant to open each */
    /* coms[j] to mis[j] at position i   */
    fn verify(
        ck: &Self::CommitmentKey,
        i: usize,
        mis: &Vec<F>,
        coms: &Vec<Self::Commitment>,
        opening: &Self::Opening,
    ) -> bool;
}
