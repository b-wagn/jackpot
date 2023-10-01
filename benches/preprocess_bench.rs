use criterion::{black_box, Criterion};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};

// benchmark preprocessing of jack for 2^{ld}-2 lotteries
fn bench(c: &mut Criterion, ld: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    // we reuse par for both Jack and JackPre to
    // decrease waiting time for the user
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    // benchmark jack
    let label = format!("preprocess_jack_{}", ld);
    c.bench_function(&label, |b| {
        let (_pk, mut sk) = <Jack as LotteryScheme>::gen(&mut rng, black_box(&par));
        b.iter(|| Jack::fk_preprocess(black_box(&par), &mut sk));
    });
}

pub fn preprocess_bench(c: &mut Criterion) {
    bench(c, 10);
    bench(c, 15);
    bench(c, 20);
}
