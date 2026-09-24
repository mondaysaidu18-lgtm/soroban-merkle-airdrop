//! Fuzz target for `merkle::verify_proof` — Issue #30.
//!
//! Exercises the Merkle proof verifier with arbitrary byte inputs to catch
//! panics, out-of-bounds accesses, and other undefined behaviour that would
//! not be reached by the deterministic unit tests.
//!
//! # What we are testing
//!
//! `verify_proof` must **never panic** regardless of what bytes are supplied
//! for the root, the leaf hash, or the proof elements.  It may return `true`
//! or `false`, but it must not crash.
//!
//! # Running
//!
//! ```sh
//! cargo fuzz run verify_proof -- -max_total_time=60
//! ```
//!
//! A crash corpus entry will be written to `fuzz/artifacts/verify_proof/` and
//! can be replayed with:
//!
//! ```sh
//! cargo fuzz run verify_proof fuzz/artifacts/verify_proof/<file>
//! ```
//!
//! # Structure of the fuzz input
//!
//! The raw fuzzer input is a flat byte buffer interpreted as follows:
//!
//! ```
//! [0..32]   — root hash (BytesN<32>)
//! [32..64]  — leaf hash (BytesN<32>)
//! [64]      — number of proof elements N  (0–7, masked to 3 bits)
//! [65..]    — N × 32-byte proof sibling hashes
//! ```
//!
//! Inputs shorter than 65 bytes (or that don't provide enough bytes for N
//! proof elements) are simply skipped — libFuzzer will quickly learn to
//! generate inputs of the appropriate length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_sdk::{BytesN, Env, Vec};

// Re-export the merkle module from the contract crate.
// The crate must be compiled with the `rlib` crate type (already set in
// contracts/airdrop/Cargo.toml via `crate-type = ["cdylib", "rlib"]`).
use soroban_merkle_airdrop::merkle;

fuzz_target!(|data: &[u8]| {
    // Minimum input: 32 (root) + 32 (leaf) + 1 (proof len byte) = 65 bytes.
    if data.len() < 65 {
        return;
    }

    let env = Env::default();

    // ── Root hash ──────────────────────────────────────────────────────────
    let root_bytes: [u8; 32] = data[0..32].try_into().unwrap();
    let root = BytesN::<32>::from_array(&env, &root_bytes);

    // ── Leaf hash ──────────────────────────────────────────────────────────
    let leaf_bytes: [u8; 32] = data[32..64].try_into().unwrap();
    let leaf = BytesN::<32>::from_array(&env, &leaf_bytes);

    // ── Proof length — cap at 7 to keep each fuzz invocation fast ──────────
    let n_proof = (data[64] & 0x07) as usize; // 0–7 siblings

    // ── Proof elements ─────────────────────────────────────────────────────
    let needed = 65 + n_proof * 32;
    if data.len() < needed {
        return; // not enough bytes for the requested proof length
    }

    let mut proof: Vec<BytesN<32>> = Vec::new(&env);
    for i in 0..n_proof {
        let start = 65 + i * 32;
        let sib: [u8; 32] = data[start..start + 32].try_into().unwrap();
        proof.push_back(BytesN::<32>::from_array(&env, &sib));
    }

    // ── Invoke the verifier — must NOT panic ───────────────────────────────
    // The return value (`true` / `false`) is intentionally ignored: the
    // fuzzer's only job is to ensure the function terminates without a panic.
    let _ = merkle::verify_proof(&env, &root, leaf, &proof);
});
