# Jackpot: Non-Interactive Aggregatable Lotteries

Implementation of the Jackpot lottery scheme in Rust using [arkworks](http://arkworks.rs/).

Disclaimer: This implementation is prototypical and not safe for production use.

## Background
Jackpot is a non-interactive lottery scheme for which winning tickets can be publicly aggregated into a single short winning ticket.
This is in contrast to the folklore lottery scheme, where in every lottery round, every party signs a common seed and wins if `H(signature) < T` for some threshold `T`.
Jackpot is based on a simulation-extractable variant of [KZG commitments](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf).
Combined with a broadcast channel and a randomness beacon, it has been proven to yield a UC secure lottery protocol.

## Overview

### Lottery Scheme Trait
A trait defining a lottery scheme is provided.
The trait is `ni_agg_lottery::lotteryscheme::LotteryScheme`.

### Implemented Lottery Schemes
To evaluate Jackpot, we have implemented both Jackpot and the folklore lottery scheme using [arkworks](http://arkworks.rs/).
We also implemented the [FK technique](https://eprint.iacr.org/2023/033.pdf) for precomputing all tickets.
This is optional and may be done in the background by calling `Jack::fk_preprocess`.

### Example of Usage
We use Jack as an example, but any type implementing the trait `LotteryScheme` would work similarly.
The following code shows how to generate parameters and keys:
```rust

    let mut rng = ark_std::rand::thread_rng();
    // for Jack, the number of lotteries
    // should always be 2^d - 2 for some d
    let num_lotteries = (1 << 4) - 2;
    // winning with probability 1/k
    let k = 512;
    // generate system parameters
    let par = <Jack as LotteryScheme>::setup(&mut rng, num_lotteries, k);
    // generate a few users with their keys
    let mut pks = Vec::new();
    let mut sks = Vec::new();
    let mut pids = Vec::new();
    for j in 0..5 {
        let (pk, sk) = <Jack as LotteryScheme>::gen(&mut rng, &par);
        pks.push(pk);
        sks.push(sk);
        pids.push(j as u32);
    }
    // optionally, we can precompute openings
    // this may take a while, depending on the
    // number of lotteries
    Jack::fk_preprocess(&par, &mut sks[0]);
```
The following code shows how to do a lottery:
```rust
    // do a lottery
    // say we do the first lottery (i = 0);
    // in practice, we should sample lseed using a
    // distributed randomness beacon
    let i = 0;
    let lseed = <Jack as LotteryScheme>::sample_seed(&mut rng, &par, i);
    for j in 0..5 {
        // check for each user if it won
        // and if so, generate its ticket
        if <Jack as LotteryScheme>::participate(&par, i, &lseed, pids[j], &sks[j], &pks[j]) {
            // player won
            let ticket =
               <Jack as LotteryScheme>::get_ticket(&par, i, &lseed, pids[j], &sks[j], &pks[j])
                    .unwrap();
            // now we could safe the ticket for aggregating it later
            // or send it to someone to prove that we won
        }
    }
```
We can easily aggregate tickets as follows:
```rust
    let i, lseed = // ... as above, lottery number and seed
    let pks = // ... the keys of the winning players
    let pids = // ... their ids
    let tickets = // ... their tickets
    // aggregate
    let ticket = <Jack as LotteryScheme>::aggregate(&par, i, &lseed, &pids, &pks, &tickets);
```
Now, we can verify:
```rust
    let result = <Jack as LotteryScheme>::verify(&par, i, &lseed, &pids, &pks, &ticket);
```

## Tests
You can run all tests with `cargo test`.

## Benchmarks
You can run the benchmarks with `cargo bench`.

## Memory Table from the Paper
We have generated the table comparing bandwidth/memory of Jack and the BLS+Hash scheme with the Python script `storage_table.py`.

## Licence
MIT License.
