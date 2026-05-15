//! Spartan2 prove/verify CLI for the SLH-DSA-128s Poseidon-hash circuit.
//!
//! Usage:
//!   cargo run --release -- setup     --input ../circom/inputs/slh_dsa/1k/default.json
//!   cargo run --release -- prove     --input ../circom/inputs/slh_dsa/1k/default.json
//!   cargo run --release -- verify
//!   cargo run --release -- benchmark --input ../circom/inputs/slh_dsa/1k/default.json
//!
//! `setup` does NOT need a satisfying witness — the circuit's R1CS structure
//! alone is enough. `prove`/`verify`/`benchmark` require a valid signature
//! witness; see Note in README about generating one.

use slh_dsa_spartan2::{
    paths::{INSTANCE, PROOF, PROVING_KEY, VERIFYING_KEY, WITNESS_FILE},
    prove_circuit, prove_circuit_with_pk, setup_circuit_keys, verify_circuit, PathConfig,
    SlhDsaCircuit,
};
use std::{
    env::args,
    fs,
    path::PathBuf,
    process,
    time::Instant,
};
use tracing_subscriber::EnvFilter;

fn get_file_size(path: &str) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[derive(Default, Debug)]
struct BenchmarkResults {
    setup_ms: Option<u128>,
    prep_prove_ms: Option<u128>,
    prove_ms: Option<u128>,
    verify_ms: Option<u128>,
    pk_bytes: u64,
    vk_bytes: u64,
    proof_bytes: u64,
}

impl BenchmarkResults {
    fn print(&self) {
        println!();
        println!("╔════════════════════════════════════════════════════╗");
        println!("║   SLH-DSA-128s (Poseidon) — Spartan2 benchmark     ║");
        println!("║   Message size: 1024 B  |  Backend: T256HyraxEngine║");
        println!("╠════════════════════════════════════════════════════╣");
        println!("║ TIMING                                             ║");
        println!("╠════════════════════════════════════════════════════╣");
        if let Some(ms) = self.setup_ms {
            println!("║ Setup:        {:>10} ms                       ║", ms);
        }
        if let Some(ms) = self.prep_prove_ms {
            println!("║ Prep Prove:   {:>10} ms                       ║", ms);
        }
        if let Some(ms) = self.prove_ms {
            println!("║ Prove:        {:>10} ms                       ║", ms);
        }
        if let Some(ms) = self.verify_ms {
            println!("║ Verify:       {:>10} ms                       ║", ms);
        }
        println!("╠════════════════════════════════════════════════════╣");
        println!("║ SIZES                                              ║");
        println!("╠════════════════════════════════════════════════════╣");
        println!("║ Proving Key:  {:>12}                         ║", format_size(self.pk_bytes));
        println!("║ Verifying Key:{:>12}                         ║", format_size(self.vk_bytes));
        if self.proof_bytes > 0 {
            println!("║ Proof:        {:>12}                         ║", format_size(self.proof_bytes));
        }
        println!("╚════════════════════════════════════════════════════╝");
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with_target(false)
        .init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: slh-dsa-spartan2 <setup|prove|verify|benchmark> [--input <path>]");
        process::exit(1);
    }

    let cmd = argv[1].as_str();
    let input_path = parse_input_arg(&argv);

    let path_config = PathConfig::default();

    match cmd {
        "setup" => {
            let circuit = SlhDsaCircuit::new(path_config.clone(), input_path);
            let (_pk, _vk, setup_ms) = setup_circuit_keys(circuit, PROVING_KEY, VERIFYING_KEY);
            let mut r = BenchmarkResults::default();
            r.setup_ms = Some(setup_ms);
            r.pk_bytes = get_file_size(PROVING_KEY);
            r.vk_bytes = get_file_size(VERIFYING_KEY);
            r.print();
        }
        "prove" => {
            let input = input_path.expect("--input required for prove");
            let circuit = SlhDsaCircuit::new(path_config, Some(input));
            let (prep_ms, prove_ms) = prove_circuit(circuit, PROVING_KEY, PROOF);
            let mut r = BenchmarkResults::default();
            r.prep_prove_ms = Some(prep_ms);
            r.prove_ms = Some(prove_ms);
            r.pk_bytes = get_file_size(PROVING_KEY);
            r.proof_bytes = get_file_size(PROOF);
            r.print();
        }
        "verify" => {
            let (_pubs, verify_ms) = verify_circuit(PROOF, VERIFYING_KEY);
            let mut r = BenchmarkResults::default();
            r.verify_ms = Some(verify_ms);
            r.vk_bytes = get_file_size(VERIFYING_KEY);
            r.proof_bytes = get_file_size(PROOF);
            r.print();
            println!("VERIFY OK");
        }
        "benchmark" => {
            let input = input_path.expect("--input required for benchmark");
            let circuit = SlhDsaCircuit::new(path_config, Some(input));

            let mut r = BenchmarkResults::default();

            // Setup
            let t0 = Instant::now();
            let (pk, vk, setup_ms) =
                setup_circuit_keys(circuit.clone(), PROVING_KEY, VERIFYING_KEY);
            let _ = t0; // setup_ms already captured inside setup_circuit_keys
            r.setup_ms = Some(setup_ms);
            r.pk_bytes = get_file_size(PROVING_KEY);
            r.vk_bytes = get_file_size(VERIFYING_KEY);

            // Prove
            let (prep_ms, prove_ms) = prove_circuit_with_pk(circuit.clone(), &pk, PROOF);
            r.prep_prove_ms = Some(prep_ms);
            r.prove_ms = Some(prove_ms);
            r.proof_bytes = get_file_size(PROOF);

            // Verify
            let t0 = Instant::now();
            use slh_dsa_spartan2::setup::load_proof;
            use spartan2::traits::snark::R1CSSNARKTrait;
            let proof = load_proof(PROOF).expect("load proof failed");
            let _pubs = proof
                .verify(&vk)
                .expect("verify failed (R1CS unsatisfied — witness may be invalid)");
            r.verify_ms = Some(t0.elapsed().as_millis());

            r.print();
        }
        other => {
            eprintln!("Unknown command: {}", other);
            process::exit(1);
        }
    }

    // Suppress unused-import warnings.
    let _ = (INSTANCE, WITNESS_FILE);
}

fn parse_input_arg(argv: &[String]) -> Option<PathBuf> {
    let mut i = 2;
    while i < argv.len() {
        if argv[i] == "--input" && i + 1 < argv.len() {
            return Some(PathBuf::from(&argv[i + 1]));
        }
        i += 1;
    }
    None
}
