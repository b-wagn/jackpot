use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Radix2EvaluationDomain;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ni_agg_lottery::lotteryscheme::vcbased::VCLotteryScheme;
use ni_agg_lottery::lotteryscheme::LotteryScheme;
use ni_agg_lottery::vectorcommitment::VectorCommitmentScheme;
use ni_agg_lottery::vectorcommitment::kzg::VcKZG;

pub fn keygen_bench(c: &mut Criterion) {
    type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
    type F = <Bls12_381 as Pairing>::ScalarField;
    type D = Radix2EvaluationDomain<F>;
    type VC = VcKZG<Bls12_381, UniPoly381, D>;
    type VCL = VCLotteryScheme<F, VC>;
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024 - 2;
    let k = 1000;
    let par = VCL::setup(&mut rng, num_lotteries, k).unwrap();
    c.bench_function("keygen 1022 1000", |b| {
        b.iter(|| VCL::gen(&mut rng, &par));
    });
}

pub fn open_bench(c: &mut Criterion) {
    type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
    type F = <Bls12_381 as Pairing>::ScalarField;
    type D = Radix2EvaluationDomain<F>;
    type VC = VcKZG<Bls12_381, UniPoly381, D>;
    type VCL = VCLotteryScheme<F, VC>;
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024 - 2;
    let k = 1000;
    let par = VCL::setup(&mut rng, num_lotteries, k).unwrap();
    c.bench_function("open 1022 1000", |b| {
        let (pk,sk) = VCL::gen(&mut rng, &par);
        b.iter(|| VC::open(&par.ck,&sk.state,black_box(3)));
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

criterion_group!(benches, keygen_bench, open_bench);
criterion_main!(benches);
