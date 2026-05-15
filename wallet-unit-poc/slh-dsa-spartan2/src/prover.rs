use std::{path::Path, time::Instant};

use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use tracing::info;

use crate::{
    setup::{load_proving_key, load_verifying_key, save_proof},
    Scalar, E,
};

/// One-shot setup → prove → verify pipeline.
pub fn run_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(circuit: C) {
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!("setup: {} ms", setup_ms);

    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    let proof =
        R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!("prove: {} ms", prove_ms);

    let t0 = Instant::now();
    proof.verify(&vk).expect("verify failed");
    let verify_ms = t0.elapsed().as_millis();
    info!("verify: {} ms", verify_ms);

    info!(
        "SUMMARY  setup={}ms prep_prove={}ms prove={}ms verify={}ms",
        setup_ms, prep_ms, prove_ms, verify_ms
    );
}

/// Load proving key then prove and save the proof.
pub fn prove_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) -> (u128, u128) {
    let t0 = Instant::now();
    let pk = load_proving_key(&pk_path).expect("load proving key failed");
    info!("load pk: {} ms", t0.elapsed().as_millis());
    prove_circuit_with_pk(circuit, &pk, proof_path)
}

pub fn prove_circuit_with_pk<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    proof_path: impl AsRef<Path>,
) -> (u128, u128) {
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    let proof =
        R1CSSNARK::<E>::prove(pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!("prove: {} ms", prove_ms);

    save_proof(proof_path, &proof).expect("save proof failed");
    (prep_ms, prove_ms)
}

/// Load proof + vk then verify.
pub fn verify_circuit(
    proof_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) -> (Vec<Scalar>, u128) {
    let proof = crate::setup::load_proof(proof_path).expect("load proof failed");
    let vk = load_verifying_key(vk_path).expect("load vk failed");
    let t0 = Instant::now();
    let pubs = proof.verify(&vk).expect("verify failed");
    let verify_ms = t0.elapsed().as_millis();
    info!("verify: {} ms", verify_ms);
    (pubs, verify_ms)
}
