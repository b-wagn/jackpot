use criterion::{criterion_group, criterion_main};
use keygen_bench::{keygen_bench_large, keygen_bench_medium, keygen_bench_small};

mod keygen_bench;
mod participate_bench;
mod aggregate_bench;
mod verify_bench;

criterion_group!(
    benches,
    keygen_bench_small,
    keygen_bench_medium,
    keygen_bench_large
);
criterion_main!(benches);
