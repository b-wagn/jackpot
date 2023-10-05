use criterion::{criterion_group, criterion_main};

use crate::aggregate_bench::aggregate_bench;
use crate::get_ticket_bench::get_ticket_bench;
use crate::keygen_bench::keygen_bench;
use crate::verify_key_bench::verify_key_bench;
use crate::participate_bench::participate_bench;
use crate::preprocess_bench::preprocess_bench;
use crate::verify_bench::verify_bench;

mod aggregate_bench;
mod get_ticket_bench;
mod keygen_bench;
mod verify_key_bench;
mod participate_bench;
mod preprocess_bench;
mod verify_bench;

criterion_group!(
    benches,
    aggregate_bench,
    verify_bench,
    keygen_bench,
    verify_key_bench,
    participate_bench,
    get_ticket_bench,
    preprocess_bench,
);
criterion_main!(benches);
