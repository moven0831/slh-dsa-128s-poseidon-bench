//! Circom `.r1cs` + `.wtns` → bellpepper SpartanCircuit adapter for
//! Goldilocks. Uses `neo_bridge::parse_circom_r1cs` (Goldilocks-aware) for
//! parsing — that crate's `CircomR1cs` already stores constraints
//! row-oriented as `a/b/c: Vec<Vec<(wire, coeff_bytes_le)>>`, which maps
//! directly into bellpepper's `cs.enforce` linear-combination API.
//!
//! Two-phase circom convention preserved: `setup` does NOT need a witness
//! (alloc all wires as zero), `prove`/`verify` does. Distinguish via the
//! `type_name::<CS>()` check on `ShapeCS` (same pattern used by
//! `slh-dsa-spartan2`'s secq256r1 sibling).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use ff::{Field, PrimeField};
use spartan2::traits::circuit::SpartanCircuit;

use neo_bridge::{parse_circom_r1cs, parse_circom_wtns};

use crate::{Scalar, E};

/// Inner state loaded once and shared via `Arc` so `Clone` is cheap.
struct Inner {
    pub n_constraints: usize,
    pub n_wires: usize,
    pub n_pub_out: usize,
    /// Constraints in Circom row-oriented form. Each row is a list of
    /// `(wire_index, coefficient_bytes_le)` pairs over Goldilocks.
    pub a: Vec<Vec<(u32, Vec<u8>)>>,
    pub b: Vec<Vec<(u32, Vec<u8>)>>,
    pub c: Vec<Vec<(u32, Vec<u8>)>>,
    /// Pre-converted witness in Spartan2 scalar form. `None` for
    /// setup-only construction.
    pub witness: Option<Vec<Scalar>>,
}

#[derive(Clone)]
pub struct Circom2SpartanCircuit {
    inner: Arc<Inner>,
    r1cs_path: PathBuf,
    wtns_path: Option<PathBuf>,
}

impl Circom2SpartanCircuit {
    /// Load the Circom R1CS (and optionally its .wtns). The .r1cs is
    /// kept row-oriented and the witness is pre-converted to Spartan2
    /// scalars so synthesize is allocation-light.
    pub fn load(r1cs_path: impl Into<PathBuf>, wtns_path: Option<PathBuf>) -> Result<Self> {
        let r1cs_path = r1cs_path.into();
        let r1cs = parse_circom_r1cs(&r1cs_path)
            .with_context(|| format!("parsing {}", r1cs_path.display()))?;
        if r1cs.field_size_bytes != 8 {
            anyhow::bail!(
                "expected Goldilocks-sized field (8 bytes), got {} — is the .r1cs from circom --prime goldilocks?",
                r1cs.field_size_bytes
            );
        }

        let witness = if let Some(p) = &wtns_path {
            let w = parse_circom_wtns(p)
                .with_context(|| format!("parsing {}", p.display()))?;
            if w.field_size_bytes != 8 {
                anyhow::bail!(
                    "expected Goldilocks-sized witness, got {} bytes/element",
                    w.field_size_bytes
                );
            }
            if w.n_wires as usize != r1cs.n_wires as usize {
                anyhow::bail!(
                    "wire count mismatch: r1cs={}, wtns={}",
                    r1cs.n_wires, w.n_wires
                );
            }
            Some(
                w.wires_le_bytes
                    .iter()
                    .map(|bytes| bytes_to_scalar(bytes))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            None
        };

        let inner = Inner {
            n_constraints: r1cs.n_constraints as usize,
            n_wires: r1cs.n_wires as usize,
            n_pub_out: r1cs.n_pub_out as usize,
            a: r1cs.a,
            b: r1cs.b,
            c: r1cs.c,
            witness,
        };

        Ok(Self {
            inner: Arc::new(inner),
            r1cs_path,
            wtns_path,
        })
    }

    pub fn r1cs_path(&self) -> &Path { &self.r1cs_path }
    pub fn wtns_path(&self) -> Option<&Path> { self.wtns_path.as_deref() }
    pub fn n_constraints(&self) -> usize { self.inner.n_constraints }
    pub fn n_wires(&self) -> usize { self.inner.n_wires }
    pub fn n_pub_out(&self) -> usize { self.inner.n_pub_out }
    pub fn has_witness(&self) -> bool { self.inner.witness.is_some() }
}

/// Decode the little-endian Goldilocks coefficient bytes into a Spartan2
/// scalar. Pads to 8 bytes if upstream produced a shorter buffer
/// (a Circom encoding choice for small coefficients on some versions).
fn bytes_to_scalar(le_bytes: &[u8]) -> Result<Scalar> {
    let mut padded = [0u8; 8];
    if le_bytes.len() > 8 {
        anyhow::bail!("coefficient too wide for Goldilocks: {} bytes", le_bytes.len());
    }
    padded[..le_bytes.len()].copy_from_slice(le_bytes);
    // `Scalar` (= spartan2::provider::goldi::F) implements ff::PrimeField
    // with `Repr = [u8; 8]`. Use from_repr_vartime for the LE round-trip.
    let repr = <Scalar as PrimeField>::Repr::from(padded);
    let opt: Option<Scalar> = Scalar::from_repr(repr).into();
    opt.ok_or_else(|| anyhow::anyhow!("byte representation not in field"))
}

impl SpartanCircuit<E> for Circom2SpartanCircuit {
    /// Returns the public IO: the Circom convention layout is
    /// `w[0] = 1`, then `w[1..=n_pub_out]` is public outputs, then public
    /// inputs. We expose just the public outputs here (no public inputs in
    /// `main_poseidon_gl.circom`).
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        match &self.inner.witness {
            Some(w) => Ok((0..self.inner.n_pub_out).map(|i| w[1 + i]).collect()),
            // Setup phase: report zeros so the shape is right; values
            // don't matter because verify isn't called here.
            None => Ok(vec![Scalar::ZERO; self.inner.n_pub_out]),
        }
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize { 0 }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = std::any::type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        // Pre-decode every coefficient once. This catches malformed
        // .r1cs entries up front (rather than silently dropping a term
        // mid-synthesize) and amortizes the byte-decode across the
        // potentially-cloned synthesize calls (setup + prove).
        let a_dec = decode_rows(&self.inner.a)?;
        let b_dec = decode_rows(&self.inner.b)?;
        let c_dec = decode_rows(&self.inner.c)?;

        // Allocate AllocatedNum per wire. w[0] is the Circom constant-1
        // wire — allocate it explicitly with value 1 and enforce
        // `w[0] = 1` so a prover cannot rescale every constant term by
        // changing witness[0].
        let mut wires: Vec<AllocatedNum<Scalar>> = Vec::with_capacity(self.inner.n_wires);
        let w0 = AllocatedNum::alloc(cs.namespace(|| "w0"), || Ok(Scalar::ONE))?;
        cs.enforce(
            || "w0_is_one",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + w0.get_variable(),
        );
        wires.push(w0);
        for i in 1..self.inner.n_wires {
            let value = if is_setup_phase {
                Scalar::ZERO
            } else {
                self.inner.witness.as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)?[i]
            };
            let w = AllocatedNum::alloc(cs.namespace(|| format!("w{}", i)), || Ok(value))?;
            wires.push(w);
        }

        // For each Circom constraint i: <A[i], z> * <B[i], z> = <C[i], z>.
        for i in 0..self.inner.n_constraints {
            cs.enforce(
                || format!("c{}", i),
                |lc| add_row_to_lc(lc, &a_dec[i], &wires),
                |lc| add_row_to_lc(lc, &b_dec[i], &wires),
                |lc| add_row_to_lc(lc, &c_dec[i], &wires),
            );
        }
        Ok(())
    }
}

/// Pre-decode all coefficient bytes into Spartan2 scalars. Errors here
/// indicate a malformed .r1cs (or a non-Goldilocks one that slipped
/// through the header check); propagate them up rather than silently
/// dropping a term.
fn decode_rows(rows: &[Vec<(u32, Vec<u8>)>]) -> Result<Vec<Vec<(u32, Scalar)>>, SynthesisError> {
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|(idx, bytes)| {
                    bytes_to_scalar(bytes)
                        .map(|s| (*idx, s))
                        .map_err(|_| SynthesisError::Unsatisfiable)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

fn add_row_to_lc(
    mut lc: LinearCombination<Scalar>,
    row: &[(u32, Scalar)],
    wires: &[AllocatedNum<Scalar>],
) -> LinearCombination<Scalar> {
    for (wire_idx, coeff) in row {
        lc = lc + (*coeff, wires[*wire_idx as usize].get_variable());
    }
    lc
}
