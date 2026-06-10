//! Monolithic Spartan2-GL benchmark on the Goldilocks SLH-DSA-128s
//! verifier circuit (`main_poseidon_gl.r1cs`, T2.1).
//!
//! Mirrors the secq256r1 sibling crate `slh-dsa-spartan2` but swaps the
//! engine to `spartan2::provider::GoldilocksP3MerkleMleEngine`. The
//! Circom-R1CS-to-bellpepper adapter lives in `circuit.rs`; CLI in
//! `bin/slh-dsa-spartan2-gl`.

use spartan2::{provider::GoldilocksP3MerkleMleEngine, traits::Engine};

/// Spartan2 engine: Goldilocks scalar, Hash-MLE PCS, Keccak Merkle.
pub type E = GoldilocksP3MerkleMleEngine;

/// Goldilocks scalar (`spartan2::provider::goldi::F`, a `pub struct F(u64)`).
pub type Scalar = <E as Engine>::Scalar;

pub mod circuit;

pub use circuit::Circom2SpartanCircuit;
