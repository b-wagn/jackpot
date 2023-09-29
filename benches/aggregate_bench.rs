use criterion::Criterion;

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};


// benchmark aggregate of jack and jackpre for 2^{ld}-2 lotteries
fn aggregate_bench(c: &mut Criterion, ld: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    // we reuse par for both Jack and JackPre to
    // decrease waiting time for the user
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    todo!()
}

pub fn aggregate_bench_small(c: &mut Criterion) {
    aggregate_bench(c, 10);
}
pub fn aggregate_bench_medium(c: &mut Criterion) {
    aggregate_bench(c, 15);
}
pub fn aggregate_bench_large(c: &mut Criterion) {
    aggregate_bench(c, 20);
}
