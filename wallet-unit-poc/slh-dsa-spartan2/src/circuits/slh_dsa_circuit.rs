use super::synthesize_witness_only;
use crate::{
    paths::{PathConfig, CIRCUIT_NAME},
    utils::{hashmap_to_json_string, parse_slh_dsa_inputs, parse_witness, NUM_PUBLIC},
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};

// Native witnesscalc bindings — the macro generates `slh_dsa_128s_poseidon_1k_witness`.
#[cfg(all(feature = "native-witness", has_circuit_slh_dsa_1k))]
witnesscalc_adapter::witness!(slh_dsa_128s_poseidon_1k);

#[cfg(feature = "native-witness")]
pub(crate) fn call_slh_dsa_witness(
    inputs_json: &str,
) -> Result<Vec<u8>, SynthesisError> {
    #[cfg(has_circuit_slh_dsa_1k)]
    {
        return slh_dsa_128s_poseidon_1k_witness(inputs_json)
            .map_err(|_| SynthesisError::Unsatisfiable);
    }
    #[cfg(not(has_circuit_slh_dsa_1k))]
    {
        let _ = inputs_json;
        eprintln!(
            "slh_dsa_128s_poseidon_1k.cpp not compiled into this binary.\n\
             Run `cd ../circom && yarn compile:slh_dsa_1k` then `cargo build --release` again."
        );
        Err(SynthesisError::Unsatisfiable)
    }
}

#[cfg(not(feature = "native-witness"))]
pub(crate) fn call_slh_dsa_witness(_inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    Err(SynthesisError::Unsatisfiable)
}

#[derive(Debug, Clone)]
pub struct SlhDsaCircuit {
    path_config: PathConfig,
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for SlhDsaCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl SlhDsaCircuit {
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path()
    }

    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();
        if let Some(ref w) = *cache {
            return Ok(w.clone());
        }
        let witness = generate_slh_dsa_witness(
            &self.path_config,
            self.input_path.as_ref().map(|p| p.as_path()),
        )?;
        *cache = Some(witness.clone());
        Ok(witness)
    }
}

impl SpartanCircuit<E> for SlhDsaCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs =
                load_r1cs(&self.r1cs_path()).map_err(|_| SynthesisError::AssignmentMissing)?;
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;

        match load_r1cs::<Scalar>(&self.r1cs_path()) {
            Ok(r1cs) => {
                synthesize(cs, r1cs, Some(witness))?;
            }
            Err(_) => {
                synthesize_witness_only(cs, &witness, NUM_PUBLIC)?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let witness = self.get_or_generate_witness().ok();
        let mut values = Vec::with_capacity(NUM_PUBLIC);
        for idx in 1..=NUM_PUBLIC {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // No shared/committed witness rows — single-circuit benchmark.
        Ok(vec![])
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

/// Generate witness for the SLH-DSA circuit by calling witnesscalc on the input JSON.
pub fn generate_slh_dsa_witness(
    config: &PathConfig,
    input_json_path: Option<&std::path::Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    use std::fs::File;
    use std::time::Instant;
    use tracing::info;

    let json_path = input_json_path
        .map(|p| config.resolve(p))
        .ok_or(SynthesisError::AssignmentMissing)?;

    info!("Loading SLH-DSA inputs from {}", json_path.display());

    let json_file = File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;
    let json_value: serde_json::Value =
        serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

    let inputs = parse_slh_dsa_inputs(&json_value)?;
    info!("Generating witness using witnesscalc...");
    let t0 = Instant::now();

    let inputs_json = hashmap_to_json_string(&inputs)?;
    let witness_bytes = call_slh_dsa_witness(&inputs_json)?;

    info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

    let _ = CIRCUIT_NAME;
    parse_witness(&witness_bytes)
}
