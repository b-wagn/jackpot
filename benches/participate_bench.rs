use criterion::{Criterion, black_box};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};


// benchmark participate of jack and jackpre for 2^{ld}-2 lotteries
fn participate_bench(c: &mut Criterion, ld: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    // we reuse par for both Jack and JackPre to
    // decrease waiting time for the user
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    // we reuse par for both Jack and JackPre to
    // decrease waiting time for the user
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    // benchmark jack
    let label = format!("participate_jack_{}", ld);
    c.bench_function(&label, |b| {
        let (pk,sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
        b.iter(|| <Jack as LotteryScheme>::participate(&par, black_box(2), &[0x03;32], 132, &sk, &pk));
    });
}

pub fn participate_bench_small(c: &mut Criterion) {
    participate_bench(c, 10);
}
pub fn participate_bench_medium(c: &mut Criterion) {
    participate_bench(c, 15);
}
pub fn participate_bench_large(c: &mut Criterion) {
    participate_bench(c, 20);
}
