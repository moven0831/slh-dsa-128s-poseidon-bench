use spartan2::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

pub mod circuits;
pub mod paths;
pub mod prover;
pub mod setup;
pub mod utils;

pub use circuits::slh_dsa_circuit::SlhDsaCircuit;
pub use paths::PathConfig;
pub use prover::{prove_circuit, prove_circuit_with_pk, run_circuit, verify_circuit};
pub use setup::{
    load_proof, load_proving_key, load_verifying_key, save_keys, save_proof, setup_circuit_keys,
};
pub use utils::{bigint_to_scalar, parse_slh_dsa_inputs, parse_witness};
