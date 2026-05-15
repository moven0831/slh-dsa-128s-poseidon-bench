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

The Poseidon-SLH-DSA-128s scheme is **non-standard** — circomlib's BN254 Poseidon constants reused over secq256r1 (which in circom 2.2.3 is the secp256r1 base field). A JS signer is checked in upstream at [moven0831/slh-dsa-circuit/scripts/poseidon_sign.mjs](https://github.com/moven0831/slh-dsa-circuit/blob/main/scripts/poseidon_sign.mjs); the resulting fixture (50 KB) ships at `../circom/inputs/slh_dsa/1k/default.json`.

To regenerate (deterministic, ~22 min on M3):

```sh
cd ../../../slh-dsa-circuit
FORK_INPUTS=../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k \
  bash scripts/regen_slh_dsa_input.sh
```

## Measured numbers (M3, 24 GB)

| Phase  | Time      | Peak RSS | Artifact      | Size      |
|--------|----------:|---------:|---------------|----------:|
| Setup  | 23,143 ms | 10.45 GB | Proving key   | 2.37 GB   |
| Prove  | 16,184 ms |  5.41 GB | Proof         | 208.8 KB  |
| Verify |  9,522 ms |  3.11 GB | Verifying key | 2.37 GB   |

Witness gen (witnesscalc) ~10 s; PK+VK size is large because this Spartan2 fork's `VerifierKey` bundles the full preprocessed R1CS shape — the on-wire proof is the small artifact. Closest comparable on the same stack: ecdsa-spartan2 `jwt_1k` (Prove 1.1 s, Verify 0.74 s, PK 257 MB). The ~10× gap tracks the R1CS-size ratio.
