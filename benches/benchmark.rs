use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use ark_poly_commit::kzg10::{Powers, KZG10};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ni_agg_lottery::lotteryscheme::jack::Jack;
use ni_agg_lottery::lotteryscheme::jack::get_jack_parameters;
use ni_agg_lottery::lotteryscheme::LotteryScheme;
use ni_agg_lottery::lotteryscheme::jack_pre::JackPre;



pub fn keygen_bench(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024 - 2;
    let k = 1000;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    c.bench_function("keygen 1022 1000", |b| {
        b.iter(|| <Jack as LotteryScheme>::gen(&mut rng, &par));
    });
}

pub fn keygen_fk_bench(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024 - 2;
    let k = 1000;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    c.bench_function("keygen_fk 1022 1000", |b| {
        b.iter(|| {
            <JackPre as LotteryScheme>::gen(&mut rng, &par);
        });
    });
}

pub fn kzg_bench(c: &mut Criterion) {
    type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
    let degree = 1023;
    let mut rng = ark_std::rand::thread_rng();
    let params =
        KZG10::<Bls12_381, UniPoly381>::setup(degree, false, &mut rng).expect("Setup failed");

    let powers_of_g = params.powers_of_g[..=1023].to_vec();
    let powers_of_gamma_g = (0..=1023).map(|i| params.powers_of_gamma_g[&i]).collect();
    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    c.bench_function("kzg 1022 1000", |b| {
        let secret_poly = UniPoly381::rand(1023, &mut rng);
        b.iter(|| {
            KZG10::<Bls12_381, UniPoly381>::commit(
                &powers,
                &secret_poly,
                Some(1022),
                Some(&mut rng),
            )
            .expect("failed to commit");
        });
    });
}


// pub fn participate_bench(c: &mut Criterion) {
//     c.bench_function("participate 1022 1000", |b| {
//         type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
//         type F = <Bls12_381 as Pairing>::ScalarField;
//         type D = Radix2EvaluationDomain<F>;
//         type VC = VcKZG<Bls12_381, UniPoly381, D>;
//         type VCL = VCLotteryScheme<F, VC>;
//         let mut rng = ark_std::rand::thread_rng();
//         let num_lotteries = 1024 - 2;
//         let k = 1000;
//         let par = VCL::setup(&mut rng, num_lotteries, k).unwrap();
//         let (pk,sk) = VCL::gen(&mut rng, &par);
//         b.iter(|| VCL::participate());
//     });
// }

criterion_group!(benches, keygen_bench, keygen_fk_bench, kzg_bench);
criterion_main!(benches);
