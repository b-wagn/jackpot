# Jackpot: Non-Interactive Aggregatable Lotteries

Implementation of the Jackpot lottery scheme in Rust using [arkworks](http://arkworks.rs/).

Disclaimer: This implementation is prototypical and not safe for production use.

## Background
Jackpot is a non-interactive lottery scheme for which winning tickets can be publicly aggregated into a single short winning ticket.
This is in contrast to the folklore lottery scheme, where in every lottery round, every party signs a common seed and wins if `H(signature) < T` for some threshold `T`.
Jackpot is based on a simulation-extractable variant of KZG commitments.
Combined with a broadcast channel and a randomness beacon, it has been proven to yield a UC secure lottery protocol.

## Example of Usage
TODO

## Tests
You can run all tests with `cargo test`. 
Be aware that this may take a while, due to a costly parameter setup.

## Benchmarks
TODO

## Licence
MIT License.
