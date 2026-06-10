//! CLI: setup / prove / verify on the Goldilocks SLH-DSA-128s monolithic
//! circuit. Mirrors `slh-dsa-spartan2`'s shape but talks to Spartan2-GL.
//!
//! Usage:
//!   slh-dsa-spartan2-gl setup     --r1cs build/main_poseidon_gl/main_poseidon_gl.r1cs
//!   slh-dsa-spartan2-gl prove     --r1cs … --wtns …
//!   slh-dsa-spartan2-gl verify    --r1cs … --wtns …
//!   slh-dsa-spartan2-gl benchmark --r1cs … --wtns …
//!
//! `setup` does not need a witness. `prove`/`verify`/`benchmark` do — see
//! the README for how to produce a Goldilocks .wtns.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use spartan2::{spartan::R1CSSNARK, traits::snark::R1CSSNARKTrait};

use slh_dsa_spartan2_gl::{Circom2SpartanCircuit, E};

type Snark = R1CSSNARK<E>;

#[derive(Parser, Debug)]
#[command(name = "slh-dsa-spartan2-gl")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Setup {
        #[arg(long)] r1cs: PathBuf,
    },
    Prove {
        #[arg(long)] r1cs: PathBuf,
        #[arg(long)] wtns: PathBuf,
    },
    Verify {
        #[arg(long)] r1cs: PathBuf,
        #[arg(long)] wtns: PathBuf,
    },
    Benchmark {
        #[arg(long)] r1cs: PathBuf,
        #[arg(long)] wtns: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Args::parse().cmd {
        Cmd::Setup { r1cs } => {
            let circuit = Circom2SpartanCircuit::load(r1cs, None)?;
            describe(&circuit);
            let t = Instant::now();
            let (_pk, _vk) = Snark::setup(circuit).map_err(|e| anyhow::anyhow!("setup: {e:?}"))?;
            println!("setup: {} ms", t.elapsed().as_millis());
        }
        Cmd::Prove { r1cs, wtns } => {
            let circuit = Circom2SpartanCircuit::load(r1cs, Some(wtns))?;
            describe(&circuit);
            let (pk, _vk) = time("setup", || Snark::setup(circuit.clone()))?;
            let prep = time("prep_prove", || Snark::prep_prove(&pk, circuit.clone(), true))?;
            let _proof = time("prove", || Snark::prove(&pk, circuit, &prep, true))?;
        }
        Cmd::Verify { r1cs, wtns } => {
            let circuit = Circom2SpartanCircuit::load(r1cs, Some(wtns))?;
            describe(&circuit);
            let (pk, vk) = time("setup", || Snark::setup(circuit.clone()))?;
            let prep = time("prep_prove", || Snark::prep_prove(&pk, circuit.clone(), true))?;
            let proof = time("prove", || Snark::prove(&pk, circuit, &prep, true))?;
            let _io = time("verify", || proof.verify(&vk))?;
            println!("RESULT: PASS — Spartan2-GL prove + verify on Goldilocks SLH-DSA-128s.");
        }
        Cmd::Benchmark { r1cs, wtns } => {
            let circuit = Circom2SpartanCircuit::load(r1cs, Some(wtns))?;
            describe(&circuit);
            let t_total = Instant::now();
            let (pk, vk) = time("setup", || Snark::setup(circuit.clone()))?;
            let prep = time("prep_prove", || Snark::prep_prove(&pk, circuit.clone(), true))?;
            let proof = time("prove", || Snark::prove(&pk, circuit, &prep, true))?;
            let _io = time("verify", || proof.verify(&vk))?;
            println!("Total wall-clock: {} ms", t_total.elapsed().as_millis());
            let pk_bytes = bincode::serialize(&pk).context("serialize pk")?.len();
            let vk_bytes = bincode::serialize(&vk).context("serialize vk")?.len();
            let proof_bytes = bincode::serialize(&proof).context("serialize proof")?.len();
            println!("pk: {} B  vk: {} B  proof: {} B", pk_bytes, vk_bytes, proof_bytes);
        }
    }
    Ok(())
}

fn describe(circuit: &Circom2SpartanCircuit) {
    println!(
        "r1cs:        {}",
        circuit.r1cs_path().display()
    );
    if let Some(w) = circuit.wtns_path() {
        println!("wtns:        {}", w.display());
    }
    println!(
        "constraints: {}  wires: {}  pub_out: {}  witness loaded: {}",
        circuit.n_constraints(),
        circuit.n_wires(),
        circuit.n_pub_out(),
        circuit.has_witness(),
    );
}

fn time<T, E: std::fmt::Debug>(
    label: &str,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T> {
    let t = Instant::now();
    let r = f().map_err(|e| anyhow::anyhow!("{label}: {e:?}"))?;
    println!("{}: {} ms", label, t.elapsed().as_millis());
    Ok(r)
}
