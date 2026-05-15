# slh-dsa-spartan2

Spartan2 prove/verify CLI for the **SLH-DSA-128s (Poseidon hash, 1 KB message)**
verification circuit, modeled on the sibling `ecdsa-spartan2` crate.

Same backend (`T256HyraxEngine` / secq256r1 / Hyrax-PC) so the timings are
directly comparable to the ECDSA-JWT numbers in `../ecdsa-spartan2`.

## Circuit

- Source: `../circom/circuits/slh_dsa/main_poseidon.circom`
- R1CS: 3,992,159 constraints, 3,861,768 wires, 1,056 public inputs, 7,856 private inputs
- Field: secq256r1
- Hash: circomlib Poseidon (BN254-tuned constants reused over secq256r1 — **non-standard**, benchmarking only)
- Message size: fixed at 1024 B

## Prerequisites

```sh
# 1) Compile the Circom circuit (≈ 1 min, peak RSS < 2 GB)
cd ../circom
yarn install
yarn compile:slh_dsa_1k
```

This produces `build/cpp/slh_dsa_128s_poseidon_1k.{cpp,dat}` (consumed by `witnesscalc-adapter`) and `build/slh_dsa_128s_poseidon_1k/slh_dsa_128s_poseidon_1k.r1cs` (consumed by `circom-scotia`).

## Build

```sh
cd ../slh-dsa-spartan2
cargo build --release
```

First build is slow (~10–15 min) because `witnesscalc-adapter` compiles the 30 MB `.cpp` witness generator into a static lib. Incremental rebuilds are seconds.

## Run

```sh
# Setup only — does NOT need a satisfying witness. Produces proving + verifying keys.
cargo run --release -- setup

# End-to-end (needs a valid signature witness JSON):
cargo run --release -- prove     --input ../circom/inputs/slh_dsa/1k/default.json
cargo run --release -- verify

# One-shot benchmark:
cargo run --release -- benchmark --input ../circom/inputs/slh_dsa/1k/default.json
```

## Witness fixture

The Poseidon-SLH-DSA-128s scheme is **non-standard** — circomlib's BN254 Poseidon constants reused over secq256r1. No existing Rust/JS library implements signing under this scheme, so the witness fixture has to be produced by a custom signer.

A scaffolding signer is **not** yet checked in (it's a few hundred lines and the BN254→secq256r1 Poseidon parameter port is a separate task). `setup` runs without one; `prove`/`verify`/`benchmark` will fail until `../circom/inputs/slh_dsa/1k/default.json` is populated.

## Memory

This circuit is ~3–4× larger than `ecdsa-spartan2`'s biggest variant (`jwt_8k`, 1.5 GB proving key, 7 s prove on M5/24 GB). On a 24 GB M3, expect:
- Proving key: 3–6 GB
- Peak RSS during setup: 8–16 GB
- Run with other apps closed; if `setup` OOMs, document the peak and rerun on a 32 GB+ host.
