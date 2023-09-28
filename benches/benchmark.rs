use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jackpot::lotteryscheme::jack::get_jack_parameters;
use jackpot::lotteryscheme::jack::Jack;
use jackpot::lotteryscheme::jack_pre::JackPre;
use jackpot::lotteryscheme::LotteryScheme;

pub fn keygen_bench(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024 - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    c.bench_function("keygen 1022 512", |b| {
        b.iter(|| <Jack as LotteryScheme>::gen(&mut rng, &par));
    });
}

pub fn keygen_bench_large(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << 20) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    c.bench_function("keygen 2^{20} 512", |b| {
        b.iter(|| <Jack as LotteryScheme>::gen(&mut rng, &par));
    });
}

pub fn keygen_fk_bench(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = 1024 - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    c.bench_function("keygen_fk 1022 512", |b| {
        b.iter(|| {
            <JackPre as LotteryScheme>::gen(&mut rng, &par);
        });
    });
}

// TODO: This is running way to long due to 100 times repetition.
pub fn keygen_fk_bench_large(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << 20) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);
    c.bench_function("keygen_fk 2^{20} 512", |b| {
        b.iter(|| {
            <JackPre as LotteryScheme>::gen(&mut rng, &par);
        });
    });
}

criterion_group!(benches, keygen_bench, keygen_bench_large, keygen_fk_bench);
criterion_main!(benches);
