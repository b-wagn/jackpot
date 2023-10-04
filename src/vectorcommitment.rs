use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

/// module that contains a KZG-based
/// simulation-extractable (aggregatable)
/// vector commitment scheme
pub mod kzg;

/// trait representing vector commitment schemes
pub trait VectorCommitmentScheme<F: Field> {
    type CommitmentKey;
    type Commitment: CanonicalSerialize;
    type Opening;
    type State;

    /// Set up commitment key. Ideally, this should be implemented by a distributed protocol
    fn setup<R: Rng>(rng: &mut R, message_length: usize) -> Option<Self::CommitmentKey>;

    /// Commit to a vector m over the field
    fn commit<R: Rng>(
        rng: &mut R,
        ck: &Self::CommitmentKey,
        m: &Vec<F>,
    ) -> (Self::Commitment, Self::State);

    /// Verify that a given commitment com is well-formed
    fn verify_commitment(ck: &Self::CommitmentKey, com: &Self::Commitment) -> bool;

    /// Open a commitment at position i, using the state output by function commit
    fn open(ck: &Self::CommitmentKey, st: &Self::State, i: u32) -> Option<Self::Opening>;

    /// Aggregate some openings at the same position i
    /// Assuming that openings[j] is an opening for commitment
    /// coms[j] at position i to value mis[j]
    fn aggregate(
        ck: &Self::CommitmentKey,
        i: u32,
        mis: &Vec<F>,
        coms: &Vec<&Self::Commitment>,
        openings: &Vec<&Self::Opening>,
    ) -> Option<Self::Opening>;

    /// Verify an (aggregated) opening
    /// The opening is meant to open each
    /// coms[j] to mis[j] at position i
    fn verify(
        ck: &Self::CommitmentKey,
        i: u32,
        mis: &Vec<F>,
        coms: &Vec<&Self::Commitment>,
        opening: &Self::Opening,
    ) -> bool;
}

// Test functions for this trait, which can
// be used by implementors of this trait

/// test that setup works
fn _vc_test_setup<F: Field, VC: VectorCommitmentScheme<F>>() {
    let mut rng = ark_std::rand::thread_rng();

    // we test for a bunch of message lengths
    let lrange = 1..30;
    for message_length in lrange {
        // setup commitment key
        let ck = VC::setup(&mut rng, message_length);
        assert!(ck.is_some());
    }
}

/// test that honestly committing yields a valid commitment
fn _vc_test_com_ver<F: Field, VC: VectorCommitmentScheme<F>>() {
    let mut rng = ark_std::rand::thread_rng();

    // we test for a bunch of message lengths
    let lrange = 1..30;
    for message_length in lrange {
        // setup commitment key
        let ck = VC::setup(&mut rng, message_length).unwrap();
        // commit to a bunch of vectors, and then
        // check for each of them that com verifies
        let crange = 0..5;
        for _ in crange {
            // sample random vector
            let m: Vec<F> = (0..message_length).map(|_| F::rand(&mut rng)).collect();
            // commit to it
            let (com, _) = VC::commit(&mut rng, &ck, &m);
            // verify the commitment
            assert!(VC::verify_commitment(&ck, &com));
        }
    }
}

/// test that honestly committing and opening makes ver accept
fn _vc_test_opening<F: Field, VC: VectorCommitmentScheme<F>>() {
    let mut rng = ark_std::rand::thread_rng();

    // we test for a bunch of message lengths
    let lrange = 1..15;
    for message_length in lrange {
        // setup commitment key
        let ck = VC::setup(&mut rng, message_length).unwrap();

        // commit to a bunch of vectors, and then
        // check for each of them that com verifies
        let crange = 0..3;
        for _ in crange {
            // sample random vector
            let m: Vec<F> = (0..message_length).map(|_| F::rand(&mut rng)).collect();
            // commit to it
            let (com, st) = VC::commit(&mut rng, &ck, &m);

            // open the commitment at every position and verify the opening
            for i in 0..message_length {
                let op = VC::open(&ck, &st, i as u32);
                assert!(op.is_some());
                let op = op.unwrap();
                // now verify
                assert!(VC::verify(&ck, i as u32, &vec![m[i]], &vec![&com], &op));
            }

            // make sure that opening outside of the range
            // does not give an opening
            let op = VC::open(&ck, &st, message_length as u32);
            assert!(op.is_none());
        }
    }
}

/// test that honestly committing, opening, and aggregating makes ver accept
fn _vc_test_agg_opening<F: Field, VC: VectorCommitmentScheme<F>>() {
    let mut rng = ark_std::rand::thread_rng();

    // we test for a bunch of message lengths
    let lrange = 1..25;
    for message_length in lrange {
        // setup commitment key
        let ck = VC::setup(&mut rng, message_length).unwrap();

        // commit to a bunch of vectors, giving us a bunch of commitments
        let mut coms = Vec::new();
        let mut sts = Vec::new();
        let mut ms = Vec::new();
        let numcoms = 5;
        for _ in 0..numcoms {
            // sample random vector
            let m: Vec<F> = (0..message_length).map(|_| F::rand(&mut rng)).collect();
            // commit to it
            let (com, st) = VC::commit(&mut rng, &ck, &m);
            ms.push(m);
            coms.push(com);
            sts.push(st);
        }

        // Open, aggregate, verify
        for i in 0..message_length {
            let mut ops = Vec::new();
            for j in 0..numcoms {
                let op = VC::open(&ck, &sts[j], i as u32).unwrap();
                ops.push(op);
            }
            // aggregate
            let mis = (0..numcoms).map(|j| ms[j][i]).collect();
            let coms_r = (0..numcoms).map(|j| &coms[j]).collect();
            let ops_r = (0..numcoms).map(|j| &ops[j]).collect();
            let op_agg = VC::aggregate(&ck, i as u32, &mis, &coms_r, &ops_r);
            assert!(op_agg.is_some());
            let op_agg = op_agg.unwrap();
            // verify
            assert!(VC::verify(&ck, i as u32, &mis, &coms_r, &op_agg));
        }
    }
}
