# Jackpot: Non-Interactive Aggregatable Lotteries

Implementation of the Jackpot lottery scheme in Rust using [arkworks](http://arkworks.rs/).

Disclaimer: This implementation is prototypical and has not received careful code review. It not safe for production use.

## Background
Jackpot is a non-interactive lottery scheme for which winning tickets can be publicly aggregated into a single short winning ticket.
This is in contrast to the folklore lottery scheme, where in every lottery round, every party signs a common seed and wins if `H(signature) < T` for some threshold `T`.
Jackpot is based on a simulation-extractable variant of [KZG commitments](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf).
Combined with a broadcast channel and a randomness beacon, it has been proven to yield a UC secure lottery protocol.

## Overview

### Lottery Scheme Trait
In the module `lotteryscheme`, a trait `LotteryScheme` is provided.
It defines the interface a lottery scheme should have.

### Implemented Lottery Schemes
The modules `lotteryscheme::jack` and `lotteryscheme::bls_hash` contain implementors of the lottery trait, namely, the Jackpot lottery scheme and the folklore lottery scheme, respectively.
To evaluate Jackpot, we have implemented both Jackpot and the folklore lottery scheme
We also implemented the [FK technique](https://eprint.iacr.org/2023/033.pdf) for precomputing all tickets for Jackpot.
This is optional and may be done in the background by calling `Jack::fk_preprocess`.
Additionally, the module `lotteryscheme::vcbased` contains a generic implementation of lotteries from vector commitments. In fact, Jackpot is just a concrete instantiation of this generic construction using the KZG vector commitment scheme implemented in `vectorcommitment::kzg`.

### Example of Usage
We use Jack as an example, but any type implementing the trait `LotteryScheme` would work similarly.
The following code shows how to generate parameters and keys:
```rust
    // we will need some randomness
    let mut rng = ark_std::rand::thread_rng();
    // for Jack, the number of lotteries
    // should always be 2^d - 2 for some d
    let num_lotteries = (1 << 4) - 2;
    // winning probability is p = 1/k
    let k = 512;
    // generate system parameters
    let par = <Jack as LotteryScheme>::setup(&mut rng, num_lotteries, k);
    // generate a few users with keys and identifiers
    let mut pks = Vec::new();
    let mut sks = Vec::new();
    let mut pids = Vec::new();
    for j in 0..5 {
        let (pk, sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
        pks.push(pk);
        sks.push(sk);
        pids.push(j as u32);
    }
    // optionally, we can precompute tickets.
    // it may take a while, depending on the
    // number of lotteries. Also, this is a
    // feature specific to Jack and is not
    // part of the lottery trait
    Jack::fk_preprocess(&par, &mut sks[0]);
```
On registration, public keys `pk` have to be verified as follows:
```rust
    let valid : bool = <Jack as LotteryScheme>::verify_key(&par, &pk);
```
If verification fails (`valid = 0`), the key must be rejected and never be used.
The following code shows how to do a lottery:
```rust
    // let's do a lottery
    // say we do the first lottery (i = 0);
    // in practice, we should sample lseed using a
    // distributed randomness beacon
    let i = 0;
    let lseed = <Jack as LotteryScheme>::sample_seed(&mut rng, &par, i);
    for j in 0..5 {
        // check for each user if it won
        // and if so, generate its ticket
        if <Jack as LotteryScheme>::participate(&par, i, &lseed, pids[j], &sks[j], &pks[j]) {
            // participate returned that the player won
            let ticket =
               <Jack as LotteryScheme>::get_ticket(&par, i, &lseed, pids[j], &sks[j], &pks[j])
                    .unwrap();
            // we could safe the ticket for aggregating it later
            // or send it to someone to prove that we won
        }
    }
```
We can easily aggregate tickets as follows:
```rust
    let i, lseed = ... // ... as above, lottery number and seed
    let pks = ... // ... the keys of the winning players
    let pids = ... // ... their ids
    let tickets = ... // ... their tickets
    // aggregate the tickets into a single ticket
    let ticket = <Jack as LotteryScheme>::aggregate(&par, i, &lseed, &pids, &pks, &tickets);
```
Now, we can verify:
```rust
    let result : bool = <Jack as LotteryScheme>::verify(&par, i, &lseed, &pids, &pks, &ticket);
```

## Tests
You can run all tests with `cargo test`.

## Benchmarks
You can run the benchmarks with `cargo bench`.
The benchmarks are written using [criterion](https://github.com/bheisler/criterion.rs).
Be aware that running all benchmarks takes long due to the number of repetitions that criterion does.
Especially, running the benchmark `preprocess/preprocess_jack_20` takes multiple hours (while the actual preprocessing code that is being benchmarked takes less than an hour).

## Licence
MIT License.
