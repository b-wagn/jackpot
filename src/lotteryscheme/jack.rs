use std::fs::{self, File};

use super::{
    vcbased::{Parameters, VCLotteryScheme},
    LotteryScheme,
};
use crate::vectorcommitment::{
    kzg::{all_openings, VcKZG},
    VectorCommitmentScheme,
};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::Radix2EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};

type F = <Bls12_381 as Pairing>::ScalarField;
type D = Radix2EvaluationDomain<F>;
type VC = VcKZG<Bls12_381, D>;

/// Jackpot aggregatable lottery scheme,
/// instantiated with KZG over BLS12-381
pub type Jack = VCLotteryScheme<F, VC>;

/// function we use to generate system parameters for our benchmarks
/// or read it from file rto avoid doing the setup over and over again
pub fn get_jack_parameters<R: rand::Rng>(
    rng: &mut R,
    num_lotteries: usize,
    k: u32,
) -> <Jack as LotteryScheme>::Parameters {
    let dir = "crs_precomputed/".to_string();
    let path = format!("crs_precomputed/{}.crs", num_lotteries);

    // check if we already have a file containing such a commitment key
    let file = File::open(path.clone());
    println!("[INFO] Looking for parameters in file.");
    if let Ok(file) = file {
        let ck = <VC as VectorCommitmentScheme<F>>::CommitmentKey::deserialize_compressed(&file)
            .unwrap();
        let log_k = u32::BITS - k.leading_zeros() - 1;
        let par = Parameters {
            ck,
            num_lotteries,
            k,
            log_k,
        };
        println!("[INFO] Found parameters in file.");
        return par;
    }
    println!("[INFO] Did not find parameters in file. Generating new ones.");
    // otherwise, we generate it and write the commitment key to a file
    let par = <Jack as LotteryScheme>::setup(rng, num_lotteries, k).unwrap();
    // write it to a file
    let mut ck_bytes = Vec::new();
    par.ck.serialize_compressed(&mut ck_bytes).unwrap();

    fs::create_dir_all(dir).expect("fail to create directory");
    let mut file = File::create(path).expect("fail to create file");
    file.write_all(&ck_bytes).expect("fail to write to file");

    par
}

impl Jack {
    pub fn fk_preprocess(
        par: &<Jack as LotteryScheme>::Parameters,
        sk: &mut <Jack as LotteryScheme>::SecretKey,
    ) {
        all_openings(&par.ck, &mut sk.state);
    }
}

#[cfg(test)]
mod tests {
    use crate::lotteryscheme::{_lottery_test_always_winning, _lottery_test_key_verify};

    use super::Jack;

    #[test]
    fn jack_lottery_test_key_verify() {
        _lottery_test_key_verify::<Jack>();
    }

    #[test]
    fn jack_lottery_test_always_winning() {
        _lottery_test_always_winning::<Jack>();
    }
}
