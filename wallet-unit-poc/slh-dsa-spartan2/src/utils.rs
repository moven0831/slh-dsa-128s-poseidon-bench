use bellpepper_core::SynthesisError;
use num_bigint::BigInt;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr};

use crate::Scalar;

/// Parse SLH-DSA-128s Poseidon witness JSON.
///
/// Expected JSON shape (all byte arrays, decimal strings 0..255):
///   pk       : [32]          public input
///   msg      : [1024]        public input
///   r        : [16]          private input
///   sig_fors : [14][13][16]  private input (flattened)
///   sig_ht   : [7][44][16]   private input (flattened)
pub fn parse_slh_dsa_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let mut inputs = HashMap::new();
    for key in ["pk", "msg", "r"] {
        inputs.insert(key.to_string(), parse_byte_array(json_value, key)?);
    }
    inputs.insert("sig_fors".to_string(), parse_3d_byte_array(json_value, "sig_fors")?);
    inputs.insert("sig_ht".to_string(), parse_3d_byte_array(json_value, "sig_ht")?);
    Ok(inputs)
}

fn parse_byte_array(json: &Value, key: &str) -> Result<Vec<BigInt>, SynthesisError> {
    let arr = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or(SynthesisError::AssignmentMissing)?;
    arr.iter().map(parse_byte_value).collect()
}

fn parse_3d_byte_array(json: &Value, key: &str) -> Result<Vec<BigInt>, SynthesisError> {
    let outer = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or(SynthesisError::AssignmentMissing)?;
    let mut out = Vec::new();
    for mid in outer {
        let mid_arr = mid.as_array().ok_or(SynthesisError::AssignmentMissing)?;
        for inner in mid_arr {
            let inner_arr = inner.as_array().ok_or(SynthesisError::AssignmentMissing)?;
            for byte_val in inner_arr {
                out.push(parse_byte_value(byte_val)?);
            }
        }
    }
    Ok(out)
}

fn parse_byte_value(v: &Value) -> Result<BigInt, SynthesisError> {
    if let Some(s) = v.as_str() {
        BigInt::from_str(s).map_err(|_| SynthesisError::AssignmentMissing)
    } else if let Some(n) = v.as_u64() {
        Ok(BigInt::from(n))
    } else {
        Err(SynthesisError::AssignmentMissing)
    }
}

/// Convert HashMap<String, Vec<BigInt>> back to a JSON string in the shape
/// witnesscalc_adapter expects. sig_fors and sig_ht must be reconstructed
/// to their original 3D nested-array form.
pub fn hashmap_to_json_string(
    inputs: &HashMap<String, Vec<BigInt>>,
) -> Result<String, SynthesisError> {
    use serde_json::json;
    let mut out = serde_json::Map::new();

    for (k, vals) in inputs.iter() {
        let json_val = match k.as_str() {
            "sig_fors" => reshape_3d(vals, 14, 13, 16)?,
            "sig_ht" => reshape_3d(vals, 7, 44, 16)?,
            _ => {
                let s: Vec<String> = vals.iter().map(|b| b.to_string()).collect();
                json!(s)
            }
        };
        out.insert(k.clone(), json_val);
    }

    serde_json::to_string(&out).map_err(|_| SynthesisError::Unsatisfiable)
}

fn reshape_3d(
    vals: &[BigInt],
    outer: usize,
    mid: usize,
    inner: usize,
) -> Result<Value, SynthesisError> {
    use serde_json::json;
    if vals.len() != outer * mid * inner {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut out_arr = Vec::with_capacity(outer);
    for i in 0..outer {
        let mut mid_arr = Vec::with_capacity(mid);
        for j in 0..mid {
            let mut inner_arr = Vec::with_capacity(inner);
            for k in 0..inner {
                let idx = i * mid * inner + j * inner + k;
                inner_arr.push(vals[idx].to_string());
            }
            mid_arr.push(json!(inner_arr));
        }
        out_arr.push(json!(mid_arr));
    }
    Ok(json!(out_arr))
}

pub fn bigint_to_scalar(bigint_val: BigInt) -> Result<Scalar, SynthesisError> {
    let bytes = bigint_val.to_bytes_le().1;
    if bytes.len() > 32 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Scalar::from_bytes(&padded)
        .into_option()
        .ok_or(SynthesisError::Unsatisfiable)
}

pub fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<Scalar>, SynthesisError> {
    let mut pos = 0;
    if witness_bytes.len() < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 4;
    pos += 4; // version
    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let mut n8 = 0;

    for _ in 0..n_sections {
        if pos + 12 > witness_bytes.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let section_id = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let section_length =
            u64::from_le_bytes(witness_bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        match section_id {
            1 => {
                if pos + 4 > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                pos += section_length;
            }
            2 => {
                if n8 == 0 || pos + section_length > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                let witness_data = &witness_bytes[pos..pos + section_length];
                let mut scalars = Vec::with_capacity(section_length / n8);
                for chunk in witness_data.chunks(n8) {
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    let scalar = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(scalar);
                }
                return Ok(scalars);
            }
            _ => {
                pos += section_length;
            }
        }
    }
    Err(SynthesisError::Unsatisfiable)
}

/// SLH-DSA Poseidon public IO layout in the Circom witness vector:
///   witness[0]        = 1 (constant)
///   witness[1]        = valid (output)
///   witness[2..34]    = pk[0..32]
///   witness[34..1058] = msg[0..1024]
/// num_public = 1 (output) + 32 (pk) + 1024 (msg) = 1057
pub const NUM_PUBLIC: usize = 1 + 32 + 1024;
