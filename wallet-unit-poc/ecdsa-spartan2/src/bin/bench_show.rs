//! Per-config benchmark for the Show circuit.
//!
//! Pipeline (timed individually): setup → generate shared blinds → prove →
//! reblind → verify. The currently compiled `show.r1cs` / `show.cpp` (under
//! `../circom/build/show/`) defines the `Show(nClaims, maxPredicates,
//! maxLogicTokens, valueBits)` instantiation under test, so the driver script
//! is responsible for recompiling the circom side before each invocation.
//!
//! Usage:
//!   cargo run --release --bin bench_show -- \
//!     --name <config-name> \
//!     --n-claims <N> \
//!     --input <show-input.json> \
//!     --output <result.json>
//!
//! The benchmark sets `shared = [deviceKeyX, deviceKeyY, claimValues[0..nClaims]]`
//! to match the production split-R1CS layout (Prepare ↔ Show), so the reblind
//! cost reflects what a real presentation pays.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ecdsa_spartan2::{
    utils::{calculate_show_witness_indices, hashmap_to_json_string, parse_show_inputs, parse_witness},
    Scalar, E,
};
use ff::Field;
use serde::Serialize;
use spartan2::{
    bellpepper::{solver::SatisfyingAssignment, zk_r1cs::SpartanWitness},
    traits::{
        circuit::SpartanCircuit, snark::R1CSSNARKTrait, transcript::TranscriptEngineTrait, Engine,
    },
    zk_spartan::R1CSSNARK,
};
use std::{
    any::type_name,
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex},
    time::Instant,
};

witnesscalc_adapter::witness!(show);

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Args {
    name: String,
    n_claims: usize,
    input: PathBuf,
    output: PathBuf,
    r1cs: PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args::default();
    args.r1cs = PathBuf::from("../circom/build/show/show_js/show.r1cs");

    let raw: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < raw.len() {
        let take = || -> String {
            raw.get(i + 1).cloned().unwrap_or_else(|| {
                eprintln!("missing value for {}", raw[i]);
                process::exit(2);
            })
        };
        match raw[i].as_str() {
            "--name" => { args.name = take(); i += 2; }
            "--n-claims" => {
                args.n_claims = take().parse().expect("--n-claims must be a positive integer");
                i += 2;
            }
            "--input" => { args.input = PathBuf::from(take()); i += 2; }
            "--output" => { args.output = PathBuf::from(take()); i += 2; }
            "--r1cs" => { args.r1cs = PathBuf::from(take()); i += 2; }
            "--help" | "-h" => { print_usage(); process::exit(0); }
            other => {
                eprintln!("unknown argument: {}", other);
                print_usage();
                process::exit(2);
            }
        }
    }
    if args.name.is_empty() || args.input.as_os_str().is_empty() || args.output.as_os_str().is_empty() {
        eprintln!("--name, --input, and --output are required");
        print_usage();
        process::exit(2);
    }
    if args.n_claims == 0 {
        eprintln!("--n-claims must be >= 1");
        process::exit(2);
    }
    args
}

fn print_usage() {
    eprintln!(
        "Usage: bench_show --name <config> --n-claims <N> --input <path.json> \\\n  \
         --output <result.json> [--r1cs <path>]"
    );
}

// ---------------------------------------------------------------------------
// BenchShowCircuit: standalone wrapper around the currently compiled
// `show.r1cs` / `show.cpp`. Shared layout matches production.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct BenchShowCircuit {
    n_claims: usize,
    input_path: PathBuf,
    r1cs_path: PathBuf,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl BenchShowCircuit {
    fn new(n_claims: usize, input_path: PathBuf, r1cs_path: PathBuf) -> Self {
        Self {
            n_claims,
            input_path,
            r1cs_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();
        if let Some(ref w) = *cache {
            return Ok(w.clone());
        }

        let f = File::open(&self.input_path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let json: serde_json::Value =
            serde_json::from_reader(f).map_err(|_| SynthesisError::AssignmentMissing)?;
        let parsed = parse_show_inputs(&json)?;
        // The Show input has no 2D-array fields, but `hashmap_to_json_string`
        // requires dimension hints; the Show variant ignores them.
        let inputs_json = hashmap_to_json_string(&parsed, 0, 0, 0)?;
        let witness_bytes = show_witness(&inputs_json).map_err(|_| SynthesisError::Unsatisfiable)?;
        let witness = parse_witness(&witness_bytes)?;
        *cache = Some(witness.clone());
        Ok(witness)
    }
}

impl SpartanCircuit<E> for BenchShowCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        let r1cs = load_r1cs::<Scalar>(&self.r1cs_path)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        if is_setup_phase {
            synthesize(cs, r1cs, None)?;
        } else {
            let witness = self.get_or_generate_witness()?;
            synthesize(cs, r1cs, Some(witness))?;
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let witness = self.get_or_generate_witness().ok();
        let mut out = Vec::with_capacity(3);
        for idx in 1..=3 {
            out.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(out)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let layout = calculate_show_witness_indices(self.n_claims);
        let witness = {
            let cache = self.cached_witness.lock().unwrap();
            cache.clone()
        }
        .or_else(|| self.get_or_generate_witness().ok());

        let mut shared = Vec::with_capacity(2 + layout.claim_values_len);
        let dx = witness.as_ref().map(|w| w[layout.device_key_x_index]).unwrap_or(Scalar::ZERO);
        let dy = witness.as_ref().map(|w| w[layout.device_key_y_index]).unwrap_or(Scalar::ZERO);
        shared.push(AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(dx))?);
        shared.push(AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(dy))?);
        for i in 0..layout.claim_values_len {
            let v = witness
                .as_ref()
                .map(|w| w[layout.claim_values_start + i])
                .unwrap_or(Scalar::ZERO);
            shared.push(AllocatedNum::alloc(cs.namespace(|| format!("ClaimValue{i}")), || Ok(v))?);
        }
        Ok(shared)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

// ---------------------------------------------------------------------------
// Result schema (JSON written to --output)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct BenchOutput {
    name: String,
    n_claims: usize,
    timings_ms: Timings,
    sizes_bytes: Sizes,
    expression_result: bool,
}

#[derive(Debug, Serialize)]
struct Timings {
    setup: u128,
    witness_gen: u128,
    prove: u128,
    reblind: u128,
    verify: u128,
}

#[derive(Debug, Serialize)]
struct Sizes {
    proving_key: usize,
    verifying_key: usize,
    proof: usize,
    reblinded_proof: usize,
    witness: usize,
}

// ---------------------------------------------------------------------------
// Benchmark pipeline (in-memory: keys/proofs are not written to disk)
// ---------------------------------------------------------------------------

fn run(args: &Args) -> BenchOutput {
    let circuit = BenchShowCircuit::new(args.n_claims, args.input.clone(), args.r1cs.clone());

    // Pre-warm witness so the timed `prove` step doesn't include witnesscalc.
    let t0 = Instant::now();
    let witness_vec = circuit
        .get_or_generate_witness()
        .expect("witness generation failed");
    let witness_gen_ms = t0.elapsed().as_millis();

    // Setup
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();

    // Prove
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let mut transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    transcript.absorb(b"vk", &pk.vk_digest);
    let public_values = SpartanCircuit::<E>::public_values(&circuit).expect("public_values failed");
    transcript.absorb(b"public_values", &public_values.as_slice());
    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps,
        &pk.S,
        &pk.ck,
        &circuit,
        false,
        &mut transcript,
    )
    .expect("r1cs instance/witness");
    let proof =
        R1CSSNARK::<E>::prove_inner(&pk, &instance, &witness, &mut transcript).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();

    // Reblind
    let randomness: Vec<<E as Engine>::Scalar> = (0..instance.num_shared_rows())
        .map(|_| <E as Engine>::Scalar::random(ff::derive::rand_core::OsRng))
        .collect();

    let t0 = Instant::now();
    let mut reblind_transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    reblind_transcript.absorb(b"vk", &pk.vk_digest);
    let pv = instance.get_public_values();
    reblind_transcript.absorb(b"public_values", &pv);
    let (new_instance, new_witness) = SatisfyingAssignment::reblind_r1cs_instance_and_witness(
        &randomness,
        instance,
        witness,
        &pk.ck,
        &mut reblind_transcript,
    )
    .expect("reblind failed");
    let reblinded_proof = R1CSSNARK::<E>::prove_inner(
        &pk,
        &new_instance,
        &new_witness,
        &mut reblind_transcript,
    )
    .expect("reblinded prove failed");
    let reblind_ms = t0.elapsed().as_millis();

    // Verify (verify the reblinded proof, which is what the verifier sees)
    let t0 = Instant::now();
    let public_out = reblinded_proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();

    // Sizes
    let pk_bytes = bincode::serialize(&pk).expect("serialize pk").len();
    let vk_bytes = bincode::serialize(&vk).expect("serialize vk").len();
    let proof_bytes = bincode::serialize(&proof).expect("serialize proof").len();
    let reblinded_bytes = bincode::serialize(&reblinded_proof)
        .expect("serialize reblinded proof")
        .len();
    let witness_bytes = bincode::serialize(&new_witness).expect("serialize witness").len();
    let _ = witness_vec; // silence unused-warning

    let expression_result = public_out
        .first()
        .map(|s| *s == Scalar::ONE)
        .unwrap_or(false);

    BenchOutput {
        name: args.name.clone(),
        n_claims: args.n_claims,
        timings_ms: Timings {
            setup: setup_ms,
            witness_gen: witness_gen_ms,
            prove: prove_ms,
            reblind: reblind_ms,
            verify: verify_ms,
        },
        sizes_bytes: Sizes {
            proving_key: pk_bytes,
            verifying_key: vk_bytes,
            proof: proof_bytes,
            reblinded_proof: reblinded_bytes,
            witness: witness_bytes,
        },
        expression_result,
    }
}

fn write_output(path: &Path, result: &BenchOutput) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output dir");
    }
    let json = serde_json::to_string_pretty(result).expect("serialize result");
    let mut f = File::create(path).expect("create output file");
    f.write_all(json.as_bytes()).expect("write output");
    f.write_all(b"\n").ok();
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = parse_args();

    println!(
        "[bench_show] config={} n_claims={} input={} r1cs={}",
        args.name,
        args.n_claims,
        args.input.display(),
        args.r1cs.display()
    );

    let result = run(&args);

    println!(
        "  setup={}ms witness_gen={}ms prove={}ms reblind={}ms verify={}ms  expressionResult={}",
        result.timings_ms.setup,
        result.timings_ms.witness_gen,
        result.timings_ms.prove,
        result.timings_ms.reblind,
        result.timings_ms.verify,
        result.expression_result
    );

    write_output(&args.output, &result);
    println!("  → {}", args.output.display());
}
