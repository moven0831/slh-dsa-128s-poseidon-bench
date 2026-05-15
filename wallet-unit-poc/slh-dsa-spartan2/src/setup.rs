use std::{
    fs::{create_dir_all, File},
    io::{BufReader, Write},
    path::Path,
    time::Instant,
};

use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use tracing::info;

use crate::E;

pub fn save_keys(
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();
    if let Some(parent) = pk_path.parent() {
        create_dir_all(parent)?;
    }
    if let Some(parent) = vk_path.parent() {
        create_dir_all(parent)?;
    }
    let pk_bytes = bincode::serialize(pk)?;
    File::create(pk_path)?.write_all(&pk_bytes)?;
    info!("Saved proving key to: {}", pk_path.display());
    let vk_bytes = bincode::serialize(vk)?;
    File::create(vk_path)?.write_all(&vk_bytes)?;
    info!("Saved verifying key to: {}", vk_path.display());
    Ok(())
}

pub fn load_proving_key(
    pk_path: impl AsRef<Path>,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey, Box<dyn std::error::Error>> {
    let file = File::open(pk_path.as_ref())?;
    Ok(bincode::deserialize_from(&mut BufReader::new(file))?)
}

pub fn load_verifying_key(
    vk_path: impl AsRef<Path>,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey, Box<dyn std::error::Error>> {
    let file = File::open(vk_path.as_ref())?;
    Ok(bincode::deserialize_from(&mut BufReader::new(file))?)
}

pub fn save_proof(
    path: impl AsRef<Path>,
    proof: &R1CSSNARK<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = path.as_ref();
    if let Some(parent) = p.parent() {
        create_dir_all(parent)?;
    }
    let bytes = bincode::serialize(proof)?;
    File::create(p)?.write_all(&bytes)?;
    info!("Saved proof to: {}", p.display());
    Ok(())
}

pub fn load_proof(path: impl AsRef<Path>) -> Result<R1CSSNARK<E>, Box<dyn std::error::Error>> {
    let file = File::open(path.as_ref())?;
    Ok(bincode::deserialize_from(&mut BufReader::new(file))?)
}

pub fn setup_circuit_keys<C: SpartanCircuit<E> + Clone>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) -> (
    <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    u128,
) {
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!("setup: {} ms", setup_ms);
    save_keys(pk_path, vk_path, &pk, &vk).expect("save_keys failed");
    (pk, vk, setup_ms)
}
