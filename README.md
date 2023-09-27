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

TODO: Explain

### Implemented Lottery Schemes
To evaluate Jackpot, we have implemented both Jackpot and the folklore lottery scheme using [arkworks](http://arkworks.rs/).
More concretely, we provide the following implementations:

- Jack: The Jackpot scheme. See type `ni_agg_lottery::lotteryscheme::jack::Jack`.
- Jack-Pre: The Jackpot scheme with precomputed KZG openings (see [FK technique](https://eprint.iacr.org/2023/033.pdf)). Generating keys will take longer than for Jack, but participating in lotteries, i.e., computing winning tickets, is faster. See type `ni_agg_lottery::lotteryscheme::jack_pre::JackPre`.
- BLS-H: The folklore lottery scheme based on BLS signatures.

### Example of Usage
The following code shows how to generate parameters, keys, participate in a lottery, and aggregate and verify tickets.
We use Jack as an example, but any type implementing the trait `LotteryScheme` would work similarly.
TODO

## Tests
You can run all tests with `cargo test`.
Be aware that this may take a while, due to costly parameter setup.

## Benchmarks
You can run the benchmarks with `cargo bench`.

## Licence
MIT License.
