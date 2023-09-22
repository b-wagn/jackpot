use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::Radix2EvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ni_agg_lottery::lotteryscheme::LotteryScheme;
use ni_agg_lottery::lotteryscheme::vcbased::VCLotteryScheme;
use ni_agg_lottery::vectorcommitment::kzg::VcKZG;




pub fn criterion_benchmark(c: &mut Criterion) {
    type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
    type F = <Bls12_381 as Pairing>::ScalarField;
    type D = Radix2EvaluationDomain<F>;
    type VC = VcKZG<Bls12_381, UniPoly381, D>;
    type VCL = VCLotteryScheme<F,VC>;
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024-2;
    let k = 1000;
    let par = VCL::setup(&mut rng, num_lotteries, k).unwrap();

    c.bench_function("keygen 1022 1000", |b| b.iter(|| VCL::gen(&mut rng, &par) ));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);