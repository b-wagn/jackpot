use criterion::{criterion_group, criterion_main};
use crate::preprocess_bench::preprocess_bench;

mod keygen_bench;
mod preprocess_bench;
mod participate_bench;
mod aggregate_bench;
mod verify_bench;

criterion_group!(
    benches,
    preprocess_bench
);
criterion_main!(benches);
