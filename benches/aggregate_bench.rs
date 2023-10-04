use criterion::{black_box, measurement::Measurement, BenchmarkGroup, Criterion};

use jackpot::lotteryscheme::{
    jack::{get_jack_parameters, Jack},
    LotteryScheme,
};

/// benchmark aggregation of Jack for 2^log_num_tickets many tickets
fn bench<'a, M: Measurement>(c: &mut BenchmarkGroup<'a, M>, log_num_tickets: usize) {
    let mut rng = ark_std::rand::thread_rng();
    // number of lotteries should have no impact
    // on the running time of aggregate. To make sure
    // the (setup of the) benchmark does not run forever,
    // we choose num_lotteries to be small
    let num_lotteries = (1 << 4) - 2;
    let k = 512;
    let num_tickets = 1 << log_num_tickets;
    let par = get_jack_parameters(&mut rng, num_lotteries, k);

    // benchmark jack
    let label = format!("aggregate_jack_{}", log_num_tickets);
    c.bench_function(&label, |b| {
        // structure of the benchmark:
        // we need num_tickets many users and a lottery seed
        // then we aggregate their tickets
        // for Jack, it does not make a difference for
        // algorithm aggregate whether tickets are winning or not

        // Preparation 1: Generate L users
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        let mut pids = Vec::new();
        for j in 0..num_tickets {
            let (pk, sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
            pks.push(pk);
            sks.push(sk);
            pids.push(j as u32);
        }

        // Preparation 2: Do a lottery and generate all of their tickets
        let i = 0; // say we do the first lottery
        let lseed = <Jack as LotteryScheme>::sample_seed(&mut rng, &par, i);
        let mut tickets = Vec::new();
        for j in 0..num_tickets {
            let ticket =
                <Jack as LotteryScheme>::get_ticket(&par, i, &lseed, pids[j], &sks[j], &pks[j])
                    .unwrap();
            tickets.push(ticket);
        }
        // Actual Benchmark: Measure running time of aggregation
        b.iter(|| {
            <Jack as LotteryScheme>::aggregate(
                black_box(&par),
                black_box(i),
                black_box(&lseed),
                black_box(&pids),
                black_box(&pks),
                black_box(&tickets),
            );
        });
    });
}

/// benchmark aggregation of Jack
pub fn aggregate_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate");
    bench(&mut group, 0);
    bench(&mut group, 4);
    bench(&mut group, 8);
    bench(&mut group, 10);
    bench(&mut group, 11);
    group.finish();
}
