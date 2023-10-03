use criterion::{black_box, Criterion};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};

/// benchmark participate of jack for 2^{ld}-2 lotteries
fn bench(c: &mut Criterion, ld: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    // benchmark jack
    let label = format!("participate_jack_{}", ld);
    c.bench_function(&label, |b| {
        let (pk, sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
        b.iter(|| {
            <Jack as LotteryScheme>::participate(&par, black_box(2), &[0x03; 32], 132, &sk, &pk)
        });
    });
}

/// benchmark participate of jack
pub fn participate_bench(c: &mut Criterion) {
    bench(c, 10);
    bench(c, 15);
    bench(c, 20);
}
