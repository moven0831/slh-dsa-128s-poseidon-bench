//! Memory-mapped R1CS file loader.
//!
//! Loads an `.r1cs` binary file via `memmap2` so the OS can page it in lazily
//! rather than reading the entire file into a heap-allocated buffer up front.
//! This is particularly important on mobile where the sha256rsa4096 R1CS can
//! be several hundred MB.

use anyhow::{anyhow, Result};
use circom_scotia::r1cs::R1CS;
use ff::PrimeField;
use memmap2::MmapOptions;
use std::{
    collections::HashMap,
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::Path,
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Load an R1CS binary file using a memory-mapped I/O.
///
/// Equivalent to `circom_scotia::reader::load_r1cs` for binary files, but
/// uses `memmap2` instead of `BufReader<File>`.
pub fn load_r1cs_mmap<F: PrimeField>(path: impl AsRef<Path>) -> Result<R1CS<F>> {
    let mmap = {
        let file = File::open(path.as_ref())
            .map_err(|e| anyhow!("failed to open r1cs '{}': {}", path.as_ref().display(), e))?;
        // SAFETY: Opened read-only. No other process mutates this file while
        // the mapping is live. Unspecified reads (not UB) if that invariant breaks.
        unsafe { MmapOptions::new().map(&file) }
            .map_err(|e| anyhow!("mmap failed for '{}': {}", path.as_ref().display(), e))?
    };

    mmap.advise(memmap2::Advice::Sequential)
        .map_err(|e| anyhow!("madvise failed for '{}': {}", path.as_ref().display(), e))?;

    let mut cursor = Cursor::new(mmap.as_ref());
    parse_r1cs_binary(&mut cursor)
}

// ---------------------------------------------------------------------------
// Binary format helpers
// ---------------------------------------------------------------------------

fn read_u32_le(r: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le(r: &mut impl Read) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_field_element<F: PrimeField>(r: &mut impl Read) -> Result<F> {
    let mut repr = F::ZERO.to_repr();
    r.read_exact(repr.as_mut())?;
    Option::<F>::from(F::from_repr(repr))
        .ok_or_else(|| anyhow!("byte sequence is not a valid field element"))
}

fn read_constraint_vec<F: PrimeField>(r: &mut impl Read) -> Result<Vec<(usize, F)>> {
    let n = read_u32_le(r)? as usize;
    let mut vec = Vec::with_capacity(n);
    for _ in 0..n {
        let idx = read_u32_le(r)? as usize;
        let coeff = read_field_element::<F>(r)?;
        vec.push((idx, coeff));
    }
    Ok(vec)
}

// ---------------------------------------------------------------------------
// Top-level binary parser (mirrors circom-scotia's `from_reader` logic)
// ---------------------------------------------------------------------------

fn parse_r1cs_binary<F: PrimeField>(r: &mut (impl Read + Seek)) -> Result<R1CS<F>> {
    // Magic "r1cs"
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic != [0x72, 0x31, 0x63, 0x73] {
        return Err(anyhow!("not an r1cs file (bad magic)"));
    }

    let version = read_u32_le(r)?;
    if version != 1 {
        return Err(anyhow!("unsupported r1cs version {version}"));
    }

    let num_sections = read_u32_le(r)?;

    // First pass: record where each section starts and its byte length.
    let mut section_offsets = HashMap::<u32, u64>::new();
    let mut section_sizes = HashMap::<u32, u64>::new();
    for _ in 0..num_sections {
        let sec_type = read_u32_le(r)?;
        let sec_size = read_u64_le(r)?;
        let offset = r.stream_position()?;
        section_offsets.insert(sec_type, offset);
        section_sizes.insert(sec_type, sec_size);
        r.seek(SeekFrom::Current(sec_size as i64))?;
    }

    const HEADER_TYPE: u32 = 1;
    const CONSTRAINT_TYPE: u32 = 2;
    const WIRE2LABEL_TYPE: u32 = 3;

    // --- Header section ---
    r.seek(SeekFrom::Start(
        *section_offsets
            .get(&HEADER_TYPE)
            .ok_or_else(|| anyhow!("r1cs: header section missing"))?,
    ))?;

    let field_size = read_u32_le(r)?;
    if field_size != 32 {
        return Err(anyhow!(
            "r1cs: unsupported field size {field_size} (expected 32)"
        ));
    }

    // Read and validate prime against the field's own modulus.
    let mut prime_bytes = vec![0u8; field_size as usize];
    r.read_exact(&mut prime_bytes)?;
    validate_prime::<F>(&prime_bytes)?;

    let n_wires = read_u32_le(r)? as usize;
    let n_pub_out = read_u32_le(r)? as usize;
    let n_pub_in = read_u32_le(r)? as usize;
    let _n_prv_in = read_u32_le(r)?;
    let _n_labels = read_u64_le(r)?;
    let n_constraints = read_u32_le(r)? as usize;

    // --- Constraints section ---
    r.seek(SeekFrom::Start(
        *section_offsets
            .get(&CONSTRAINT_TYPE)
            .ok_or_else(|| anyhow!("r1cs: constraints section missing"))?,
    ))?;

    let mut constraints = Vec::with_capacity(n_constraints);
    for _ in 0..n_constraints {
        let a = read_constraint_vec::<F>(r)?;
        let b = read_constraint_vec::<F>(r)?;
        let c = read_constraint_vec::<F>(r)?;
        constraints.push((a, b, c));
    }

    // --- Wire2Label section (read to validate, values not needed for R1CS) ---
    r.seek(SeekFrom::Start(
        *section_offsets
            .get(&WIRE2LABEL_TYPE)
            .ok_or_else(|| anyhow!("r1cs: wire2label section missing"))?,
    ))?;
    let expected_map_bytes = (n_wires as u64) * 8;
    let actual_map_size = *section_sizes
        .get(&WIRE2LABEL_TYPE)
        .ok_or_else(|| anyhow!("r1cs: wire2label section size missing"))?;
    if actual_map_size != expected_map_bytes {
        return Err(anyhow!(
            "r1cs: wire2label size mismatch (expected {expected_map_bytes}, got {actual_map_size})"
        ));
    }
    // Read first wire label to verify it is 0 (format invariant).
    if n_wires > 0 {
        let first_label = read_u64_le(r)?;
        if first_label != 0 {
            return Err(anyhow!("r1cs: wire[0] label must be 0"));
        }
    }

    let num_inputs = 1 + n_pub_in + n_pub_out;
    let num_aux = n_wires - num_inputs;

    Ok(R1CS {
        num_pub_in: n_pub_in,
        num_pub_out: n_pub_out,
        num_inputs,
        num_aux,
        num_variables: n_wires,
        constraints,
    })
}

// ---------------------------------------------------------------------------
// Prime validation
// ---------------------------------------------------------------------------

/// Check that the 32-byte little-endian prime stored in the file matches
/// the modulus of field `F`.
///
/// `F::MODULUS` is a hex string of the form `"0x..."`.  We convert it to
/// a little-endian 32-byte array and compare byte-by-byte.
fn validate_prime<F: PrimeField>(prime_bytes: &[u8]) -> Result<()> {
    let modulus_hex = F::MODULUS; // "0x<hex digits>"
    let hex = modulus_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    // Decode hex into a big-endian byte vec, then reverse to little-endian.
    let mut be_bytes = hex::decode(hex).map_err(|e| anyhow!("bad modulus hex: {e}"))?;
    // Pad or truncate to 32 bytes.
    while be_bytes.len() < 32 {
        be_bytes.insert(0, 0);
    }
    let le_bytes: Vec<u8> = be_bytes.iter().rev().cloned().collect();

    if &le_bytes[..] != prime_bytes {
        return Err(anyhow!(
            "r1cs prime does not match field modulus (wrong curve?)"
        ));
    }
    Ok(())
}
