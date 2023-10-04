use criterion::{black_box, measurement::Measurement, BenchmarkGroup, Criterion};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};


/// benchmark preprocessing of jack for 2^{ld}-2 lotteries
fn bench<'a, M: Measurement>(c: &mut BenchmarkGroup<'a, M>, ld: usize) {
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
        b.iter(|| Jack::fk_preprocess(black_box(&par), black_box(&mut sk)));
    });
}

/// benchmark preprocessing of jack
pub fn preprocess_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess");
    // otherwise the benchmark will take too long
    group.sample_size(10);
    bench(&mut group, 10);
    bench(&mut group, 15);
    bench(&mut group, 20);
    group.finish();
}
