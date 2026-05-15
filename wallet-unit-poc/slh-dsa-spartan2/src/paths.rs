use std::path::{Path, PathBuf};

pub const CIRCUIT_NAME: &str = "slh_dsa_128s_poseidon_1k";

pub const PROVING_KEY: &str = "keys/slh_dsa_1k_pk.key";
pub const VERIFYING_KEY: &str = "keys/slh_dsa_1k_vk.key";
pub const INSTANCE: &str = "keys/slh_dsa_1k_instance.key";
pub const WITNESS_FILE: &str = "keys/slh_dsa_1k_witness.key";
pub const PROOF: &str = "keys/slh_dsa_1k_proof.key";

#[derive(Clone, Debug)]
pub struct PathConfig {
    pub base_dir: PathBuf,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

impl PathConfig {
    pub fn resolve(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base_dir.join(p)
        }
    }

    pub fn r1cs_path(&self) -> PathBuf {
        self.base_dir.join(format!(
            "../circom/build/{}/{}.r1cs",
            CIRCUIT_NAME, CIRCUIT_NAME
        ))
    }
}
