use criterion::{black_box, Criterion, BenchmarkGroup, measurement::Measurement};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};

/// benchmark participate of jack for 2^{ld}-2 lotteries
fn bench<'a, M: Measurement>(c: &mut BenchmarkGroup<'a, M>, ld: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let num_lotteries = (1 << ld) - 2;
    let k = 512;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    // benchmark jack
    let label = format!("participate_jack_{}", ld);
    c.bench_function(&label, |b| {
        let (pk, sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
        let pid = 132;
        let i = 2;
        let lseed = <Jack as LotteryScheme>::sample_seed(&mut rng, &par, i);
        b.iter(|| {
            <Jack as LotteryScheme>::participate(
                black_box(&par),
                black_box(i),
                black_box(&lseed),
                black_box(pid),
                black_box(&sk),
                black_box(&pk),
            )
        });
    });
}

/// benchmark participate of jack
pub fn participate_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("participate");
    bench(&mut group, 10);
    bench(&mut group, 15);
    bench(&mut group, 20);
    group.finish();
}
