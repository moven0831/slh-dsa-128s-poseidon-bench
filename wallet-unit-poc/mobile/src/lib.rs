use ecdsa_spartan2::{
    load_proof,
    paths::keys::{
        RS256_4096_INSTANCE, RS256_4096_PROOF, RS256_4096_PROVING_KEY, RS256_4096_VERIFYING_KEY,
        RS256_4096_WITNESS,
    },
    prover::{prove_circuit_with_pk, verify_circuit_with_loaded_data},
    save_keys,
    setup::setup_circuit_keys_no_save,
    PathConfig, Rs256FidoCircuit,
};
use std::path::PathBuf;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
mopro_ffi::app!();

// ============================================================================
// Core Types
// ============================================================================

/// Result of a proving operation with timing and proof metadata
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProofResult {
    pub prove_ms: u64,
    pub proof_size_bytes: u64,
}

/// Result of a complete benchmark run with timing and size metrics
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BenchmarkResults {
    // Timing metrics (milliseconds)
    pub setup_ms: u64,
    pub prove_ms: u64,
    pub verify_ms: u64,
    // Size metrics (bytes)
    pub proving_key_bytes: u64,
    pub verifying_key_bytes: u64,
    pub proof_bytes: u64,
    pub witness_bytes: u64,
}

impl BenchmarkResults {
    /// Format bytes into human-readable size string
    pub fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Errors that can occur during ZK proof operations
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ZkProofError {
    FileNotFound { msg: String },
    ProofGenerationFailed { msg: String },
    VerificationFailed { msg: String },
    InvalidInput { msg: String },
    SetupRequired { msg: String },
    IoError { msg: String },
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofError::FileNotFound { msg } => write!(f, "File not found: {}", msg),
            ZkProofError::ProofGenerationFailed { msg } => {
                write!(f, "Proof generation failed: {}", msg)
            }
            ZkProofError::VerificationFailed { msg } => {
                write!(f, "Verification failed: {}", msg)
            }
            ZkProofError::InvalidInput { msg } => write!(f, "Invalid input: {}", msg),
            ZkProofError::SetupRequired { msg } => write!(f, "Setup required: {}", msg),
            ZkProofError::IoError { msg } => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for ZkProofError {}

impl From<std::io::Error> for ZkProofError {
    fn from(e: std::io::Error) -> Self {
        ZkProofError::IoError {
            msg: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for ZkProofError {
    fn from(e: serde_json::Error) -> Self {
        ZkProofError::InvalidInput {
            msg: e.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn make_config(documents_path: &str) -> PathConfig {
    PathConfig::mobile(documents_path)
}

fn get_file_size(path: impl AsRef<std::path::Path>) -> Result<u64, ZkProofError> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path).map_err(|e| ZkProofError::FileNotFound {
        msg: format!("Failed to get file size from '{}': {}", path.display(), e),
    })?;
    Ok(metadata.len())
}

// ============================================================================
// Input Generation
// ============================================================================

/// Generate circuit input from a FIDO FidoSignResponse (sha256rsa4096)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_input_fido(
    certb64: String,
    signed_response: String,
    tbs: String,
    issuer_cert_path: String,
    smt_server: Option<String>,
    issuer_id: String,
    output_path: String,
) -> Result<String, ZkProofError> {
    let user_cert = Rs256FidoCircuit::generate_user_cert_from_certb64(&certb64).map_err(|e| {
        ZkProofError::InvalidInput {
            msg: e.to_string(),
        }
    })?;

    let issuer_cert = Rs256FidoCircuit::fetch_cert_from_file(&issuer_cert_path).map_err(|e| {
        ZkProofError::InvalidInput {
            msg: e.to_string(),
        }
    })?;

    Rs256FidoCircuit::generate_input(
        &user_cert,
        &signed_response,
        tbs.as_bytes(),
        &issuer_cert,
        smt_server.as_deref(),
        &issuer_id,
        &output_path,
    )
    .map_err(|e| ZkProofError::InvalidInput {
        msg: e.to_string(),
    })?;

    Ok(output_path)
}

// ============================================================================
// Setup Operation
// ============================================================================

/// Setup sha256rsa4096 circuit keys (FIDO)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_keys_fido(
    documents_path: String,
    input_path: Option<String>,
) -> Result<String, ZkProofError> {
    use ecdsa_spartan2::setup::setup_circuit_keys;
    let config = make_config(&documents_path);
    let circuit = Rs256FidoCircuit::new(config.clone(), input_path.map(PathBuf::from));

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(RS256_4096_PROVING_KEY),
        config.key_path(RS256_4096_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "sha256rsa4096 circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

// ============================================================================
// Prove Operation
// ============================================================================

/// Generate sha256rsa4096 circuit proof (FIDO)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_fido(
    documents_path: String,
    input_path: Option<String>,
) -> Result<ProofResult, ZkProofError> {
    use ecdsa_spartan2::prover::prove_circuit;
    let config = make_config(&documents_path);
    let circuit = Rs256FidoCircuit::new(config.clone(), input_path.map(PathBuf::from));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(RS256_4096_PROVING_KEY),
        config.artifact_path(RS256_4096_INSTANCE),
        config.artifact_path(RS256_4096_WITNESS),
        config.artifact_path(RS256_4096_PROOF),
    );
    let prove_ms = start.elapsed().as_millis() as u64;

    let proof_size_bytes = get_file_size(&config.artifact_path(RS256_4096_PROOF))?;

    Ok(ProofResult {
        prove_ms,
        proof_size_bytes,
    })
}

// ============================================================================
// Verify Operation
// ============================================================================

/// Verify sha256rsa4096 circuit proof (FIDO)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_fido(documents_path: String) -> Result<bool, ZkProofError> {
    use ecdsa_spartan2::prover::verify_circuit;
    let config = make_config(&documents_path);
    verify_circuit(
        config.artifact_path(RS256_4096_PROOF),
        config.key_path(RS256_4096_VERIFYING_KEY),
    );
    Ok(true)
}

// ============================================================================
// Benchmark Operation
// ============================================================================

/// Run complete benchmark pipeline for sha256rsa4096 circuit (FIDO)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark_fido(
    documents_path: String,
    input_path: Option<String>,
) -> Result<BenchmarkResults, ZkProofError> {
    let config = make_config(&documents_path);

    // Step 1: Setup
    let circuit = Rs256FidoCircuit::new(config.clone(), input_path.as_ref().map(PathBuf::from));
    let start = std::time::Instant::now();
    let (pk, vk) = setup_circuit_keys_no_save(circuit);
    let setup_ms = start.elapsed().as_millis() as u64;

    save_keys(
        config.key_path(RS256_4096_PROVING_KEY),
        config.key_path(RS256_4096_VERIFYING_KEY),
        &pk,
        &vk,
    )
    .map_err(|e| ZkProofError::IoError {
        msg: format!("Failed to save keys: {}", e),
    })?;

    // Step 2: Prove
    let circuit = Rs256FidoCircuit::new(config.clone(), input_path.as_ref().map(PathBuf::from));
    let start = std::time::Instant::now();
    prove_circuit_with_pk(
        circuit,
        &pk,
        config.artifact_path(RS256_4096_INSTANCE),
        config.artifact_path(RS256_4096_WITNESS),
        config.artifact_path(RS256_4096_PROOF),
    );
    let prove_ms = start.elapsed().as_millis() as u64;

    // Step 3: Verify
    let proof = load_proof(config.artifact_path(RS256_4096_PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            msg: format!("Failed to load proof: {}", e),
        }
    })?;

    let start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&proof, &vk);
    let verify_ms = start.elapsed().as_millis() as u64;

    let proving_key_bytes = get_file_size(&config.key_path(RS256_4096_PROVING_KEY))?;
    let verifying_key_bytes = get_file_size(&config.key_path(RS256_4096_VERIFYING_KEY))?;
    let proof_bytes = get_file_size(&config.artifact_path(RS256_4096_PROOF))?;
    let witness_bytes = get_file_size(&config.artifact_path(RS256_4096_WITNESS))?;

    Ok(BenchmarkResults {
        setup_ms,
        prove_ms,
        verify_ms,
        proving_key_bytes,
        verifying_key_bytes,
        proof_bytes,
        witness_bytes,
    })
}

// ============================================================================
// Legacy Test Function
// ============================================================================

/// Test function for basic UniFFI integration
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa_spartan2::circuits::sha256rsa_circuit::FidoSignResponse;

    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(mopro_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_path_config_mobile_rs256_fido() {
        let config = make_config("/app/Documents");
        assert_eq!(
            config.key_path(RS256_4096_PROVING_KEY),
            PathBuf::from("/app/Documents/keys/rs256_4096_proving.key")
        );
        assert_eq!(
            config.key_path(RS256_4096_VERIFYING_KEY),
            PathBuf::from("/app/Documents/keys/rs256_4096_verifying.key")
        );
        assert_eq!(
            config.artifact_path(RS256_4096_PROOF),
            PathBuf::from("/app/Documents/keys/rs256_4096_proof.bin")
        );
        assert_eq!(
            config.artifact_path(RS256_4096_WITNESS),
            PathBuf::from("/app/Documents/keys/rs256_4096_witness.bin")
        );
        assert_eq!(
            config.artifact_path(RS256_4096_INSTANCE),
            PathBuf::from("/app/Documents/keys/rs256_4096_instance.bin")
        );
    }

    #[test]
    fn test_prove_verify_fido() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let documents_path = manifest.join("../ecdsa-spartan2");
        let input_src = manifest.join("../circom/inputs/sha256rsa4096/input.json");
        prove_fido(
            documents_path.to_string_lossy().to_string(),
            Some(input_src.to_string_lossy().to_string()),
        )?;
        let verify_result = verify_fido(documents_path.to_string_lossy().to_string())?;
        assert!(verify_result);
        Ok(())
    }

    #[test]
    fn test_complete_benchmark_fido_e2e() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("Failed to create tempdir");
        let dir = tempdir.path().to_path_buf();

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let r1cs_src =
            manifest.join("../circom/build/sha256rsa4096/sha256rsa4096_js/sha256rsa4096.r1cs");
        let input_src = manifest.join("../circom/inputs/sha256rsa4096/input.json");

        assert!(
            r1cs_src.exists(),
            "R1CS not found at {}. Run `yarn compile:sha256rsa4096` first.",
            r1cs_src.display()
        );
        assert!(
            input_src.exists(),
            "Input JSON not found at {}. Run `cargo run --features sha256rsa4096 -- rs256 generate-input --fido` first.",
            input_src.display()
        );

        symlink(&r1cs_src, dir.join("sha256rsa4096.r1cs")).expect("Failed to symlink R1CS");
        symlink(&input_src, dir.join("sha256rsa4096_input.json")).expect("Failed to symlink input");
        std::fs::create_dir(dir.join("keys")).expect("Failed to create keys dir");

        // RSA-4096 witness generation is stack-heavy; run in a thread with 64 MB stack.
        let dir_str = dir.to_string_lossy().to_string();
        let results = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                run_complete_benchmark_fido(dir_str, None)
                    .expect("run_complete_benchmark_fido failed")
            })
            .expect("Failed to spawn thread")
            .join()
            .expect("Thread panicked");

        assert!(results.setup_ms > 0, "setup_ms should be > 0");
        assert!(results.prove_ms > 0, "prove_ms should be > 0");
        assert!(results.verify_ms > 0, "verify_ms should be > 0");
        assert!(
            results.proving_key_bytes > 0,
            "proving_key_bytes should be > 0"
        );
        assert!(
            results.verifying_key_bytes > 0,
            "verifying_key_bytes should be > 0"
        );
        assert!(results.proof_bytes > 0, "proof_bytes should be > 0");
        assert!(results.witness_bytes > 0, "witness_bytes should be > 0");

        let keys_dir = dir.join("keys");
        assert!(keys_dir.join("rs256_4096_proving.key").exists());
        assert!(keys_dir.join("rs256_4096_verifying.key").exists());
        assert!(keys_dir.join("rs256_4096_proof.bin").exists());
        assert!(keys_dir.join("rs256_4096_witness.bin").exists());
        assert!(keys_dir.join("rs256_4096_instance.bin").exists());

        eprintln!("\n=== sha256rsa4096 Benchmark Results ===");
        eprintln!("Setup:  {}ms", results.setup_ms);
        eprintln!("Prove:  {}ms", results.prove_ms);
        eprintln!("Verify: {}ms", results.verify_ms);
        eprintln!(
            "PK: {}, VK: {}, Proof: {}, Witness: {}",
            BenchmarkResults::format_size(results.proving_key_bytes),
            BenchmarkResults::format_size(results.verifying_key_bytes),
            BenchmarkResults::format_size(results.proof_bytes),
            BenchmarkResults::format_size(results.witness_bytes),
        );
    }

    #[ignore]
    #[test]
    fn test_generate_input_fido_e2e() {
        let fido_response_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../ecdsa-spartan2/tests/testdata/fido_response_sign.json");
        let response_string = std::fs::read_to_string(fido_response_path).unwrap();
        let response: FidoSignResponse = serde_json::from_str(&response_string).unwrap();
        let certb64 = response.result.cert;
        let signed_response = response.result.signed_response;
        let tbs = "e775f2805fb993e05a208dbff15d1c1";
        let issuer_cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../ecdsa-spartan2/tests/testdata/MOICA-G3.cer");
        let smt_server = None;
        let issuer_id = "g2";
        let output_path = "circuit_input.json".to_string();
        let _ = generate_input_fido(
            certb64,
            signed_response,
            tbs.to_string(),
            issuer_cert_path.to_string_lossy().to_string(),
            smt_server,
            issuer_id.to_string(),
            output_path.clone(),
        )
        .unwrap();
        assert!(PathBuf::from(output_path).exists());
    }
}
