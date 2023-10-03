use criterion::{black_box, Criterion};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};

/// benchmark get_ticket of jack for 2^{ld}-2 lotteries
fn bench(c: &mut Criterion, ld: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    // benchmark jack
    let label = format!("get_ticket_jack_{}", ld);
    c.bench_function(&label, |b| {
        let (pk, sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
        b.iter(|| {
            <Jack as LotteryScheme>::get_ticket(&par, black_box(2), &[0x03; 32], 132, &sk, &pk)
        });
    });
}

/// benchmark get_ticket of jacks
pub fn get_ticket_bench(c: &mut Criterion) {
    bench(c, 10);
    bench(c, 15);
    bench(c, 20);
}
