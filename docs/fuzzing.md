# Fuzzing the Merkle Proof Verifier (Issue #30)

The `fuzz/` directory contains a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
target that exercises `contracts/airdrop/src/merkle.rs::verify_proof` with
arbitrary byte inputs.

## Goal

`verify_proof` must **never panic** regardless of what bytes are supplied for
the root, the leaf, or the proof elements. The fuzzer feeds random and
mutation-driven inputs to verify this property.

## Prerequisites

```sh
# Install cargo-fuzz (requires nightly Rust)
cargo install cargo-fuzz

# Switch to nightly for the fuzz crate
rustup override set nightly
```

## Running

```sh
# Run for 60 seconds (enough for a quick smoke test)
cargo fuzz run verify_proof -- -max_total_time=60

# Run with more parallelism and longer timeout for deeper coverage
cargo fuzz run verify_proof -- -max_total_time=3600 -workers=4

# Run a specific corpus entry to reproduce a crash
cargo fuzz run verify_proof fuzz/artifacts/verify_proof/<crash-file>
```

## What is fuzzed

The fuzz input is a flat byte buffer interpreted as:

| Offset     | Length      | Meaning                                  |
|------------|-------------|------------------------------------------|
| `0..32`    | 32 bytes    | Merkle root (`BytesN<32>`)               |
| `32..64`   | 32 bytes    | Leaf hash (`BytesN<32>`)                 |
| `64`       | 1 byte      | Number of proof elements `N` (0–7)       |
| `65..`     | `N × 32 B`  | Proof sibling hashes (`BytesN<32>` each) |

Inputs shorter than 65 bytes are skipped. libFuzzer will quickly learn the
expected length from the code structure.

## Corpus

An initial seed corpus is kept in `fuzz/corpus/verify_proof/`. Add any
interesting hand-crafted inputs there to help the fuzzer explore edge cases
faster (empty proof, single-element proof, all-zero hashes, etc.).

## CI integration

The fuzz target is **not run in regular CI** because fuzz runs are
long-lived and non-deterministic. Run it locally before shipping any changes
to `contracts/airdrop/src/merkle.rs`.

To integrate into CI for a time-boxed smoke test, add a job like:

```yaml
fuzz:
  name: Fuzz smoke test (60 s)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@nightly
    - run: cargo install cargo-fuzz
    - run: cargo fuzz run verify_proof -- -max_total_time=60
```
