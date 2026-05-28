# SLH-DSA-128s with Poseidon Hash, OpenAC benchmark

End-to-end prove + verify numbers for the [SLH-DSA-128s Poseidon-hash verifier](https://github.com/moven0831/slh-dsa-circuit/blob/main/circuits/main_poseidon.circom) on two Spartan2 stacks:

1. **secq256r1 / Hyrax-PC** ([`wallet-unit-poc/slh-dsa-spartan2`](wallet-unit-poc/slh-dsa-spartan2)) — the existing OpenAC stack, `T256HyraxEngine` over secq256r1.
2. **Goldilocks / Hash-MLE PCS** ([`wallet-unit-poc/slh-dsa-spartan2-gl`](wallet-unit-poc/slh-dsa-spartan2-gl)) — `R1CSSNARK<GoldilocksP3MerkleMleEngine>` over Plonky2 Goldilocks Poseidon. Track 2 baseline for the folding experiment in [`slh-dsa-neo`](https://github.com/moven0831/slh-dsa-neo).

This fork adds both bench crates and vendors the circuits into `wallet-unit-poc/circom/circuits/slh_dsa/`. Rest is upstream [`privacy-ethereum/zkID`](https://github.com/privacy-ethereum/zkID)@`3d325e3`.

## Results (M3 / 24 GB)

### Row 1 — secq256r1 monolithic ([`slh-dsa-spartan2`](wallet-unit-poc/slh-dsa-spartan2))

`main_poseidon.circom` (circomlib BN254 Poseidon mod p_secq256r1), **3,992,159 R1CS / 3,861,768 wires / 1,056 public / 7,856 private inputs**.

| Phase   |       Time | Peak RSS |  Artifact     |     Size |
| ------- | ---------: | -------: | ------------- | -------: |
| Setup   |  23,143 ms | 10.45 GB | Proving key   |  2.37 GB |
| Witness |  1,387 ms  |        – | Verifying key |  2.37 GB |
| Prove   |  16,184 ms |  5.41 GB | **Proof**     | **208.8 KB** |
| Verify  |   9,522 ms |  3.11 GB | R1CS          |  2.28 GB |

Side notes: load pk 4,281 ms · prep_prove 20 ms.

### Row 2 — Goldilocks monolithic ([`slh-dsa-spartan2-gl`](wallet-unit-poc/slh-dsa-spartan2-gl))

`main_poseidon_gl.circom` (Plonky2 v1.1.0 Goldilocks Poseidon t=12, 30 rounds, x⁷ S-box), **3,692,597 R1CS / 3,558,276 wires / 1 public output / 8,912 private inputs**. Witness produced by the Rust Goldilocks signer in [`slh-dsa-neo/crates/slh-poseidon-gl`](https://github.com/moven0831/slh-dsa-neo/tree/main/crates/slh-poseidon-gl) (T1.1.c) and confirmed valid against the circuit (`valid == 1`).

| Phase   |       Time | Peak RSS |  Artifact     |       Size |
| ------- | ---------: | -------: | ------------- | ---------: |
| Setup   |  17,604 ms |  4.47 GB | Proving key   |     571 MB |
| Witness |   3,082 ms |  264 MB  | Verifying key |     571 MB |
| Prove   |   6,181 ms |  4.47 GB | **Proof**     | **575,198 B (562 KiB)** |
| Verify  |     273 ms |        – | R1CS          |     446 MB |

Side note: `prep_prove` 2 ms. Witness gen is the circom WASM calculator on the signer's input JSON.

These are now **real end-to-end** numbers (witness gen → setup → prove → verify, verify returns the public output `valid = 1`). Versus Row 1 (secq256r1 + Hyrax) at the same circuit scale: prove is **~2.6× faster** (6.2 s vs 16.2 s), verify is **~35× faster** (0.27 s vs 9.5 s), but the **proof is ~2.75× larger** (562 KiB vs 209 KiB) and the keys are far larger (571 MB vs 2.37 GB — Goldilocks keys are actually *smaller* here). Goldilocks R1CS is **92.5%** of the secq256r1 size (3.69M vs 3.99M).

**Attribution caveat — this gap is field *and* PCS, not pure field.** Row 1 is secq256r1 + Hyrax-PC; Row 2 is Goldilocks + Hash-MLE PCS (Keccak Merkle). The large verify speedup and the larger proof are driven mostly by the *PCS* change (Hyrax does secq256r1 MSMs at verify and yields small proofs; Hash-MLE verifies by hashing and yields larger proofs), not the field alone. To isolate pure field you'd hold the PCS fixed across both rows — out of scope here.

**Timing variance.** Measured on a loaded 24 GB M3; a second sample read setup 22.4 s / prove 8.1 s / verify 0.32 s / RSS 4.96 GB. Treat the timings as ±25%; the artifact sizes (proof, pk, vk) are deterministic. The earlier setup-only run measured 12.96 s — setup timing is the most load-sensitive cell.

### Row 3 — Goldilocks D4 folded ([`slh-dsa-neo`](https://github.com/moven0831/slh-dsa-neo))

Nightstream `r1cs_f_prime` over the same Goldilocks Poseidon family, per-XMSS-layer D4 fold of `bench_ht_layer_gl.circom` (**485,930 R1CS / 467,721 wires per step**; the bit-decomposition F' structure is `m×64+1 = 29,934,145` rows). See [`slh-dsa-neo/MEMO.md`](https://github.com/moven0831/slh-dsa-neo/blob/main/MEMO.md) for the full breakdown.

One HT-layer fold step (preprocess + 1 append + finish + uncompressed verify), M3 / 24 GB:

| Fold path                        | Preprocess | Prove+finish | Verify | Peak RSS | Witness            |
| -------------------------------- | ---------: | -----------: | -----: | -------: | ------------------ |
| 1-step, c=2 — all-zeros          |    86.7 s  |    116.6 s   | 19.8 s | 10.46 GB | synthetic          |
| **1-step, c=2 — real layer 0**   |    90.6 s  |  **139.2 s** | 28.9 s | ~10 GB   | **real, verify PASS** |
| 7-step, c=972 — real layers      |    95.7 s  | *OOM in fold* |   –   | >24 GB   | real — see ceiling note |
| 7-step + Spartan2-GL final SNARK |     –      |   *blocked*  |   –    |    –     | *Decider(Unsupported) at Nightstream 755c1595* |

The **real layer 0** row is the loop-closer: the Rust signer's `emit-layers` decomposes one signature into 7 `bench_ht_layer_gl` step witnesses (each validated to chain to `pk_root`); layer 0 folds through `r1cs_f_prime` and the uncompressed accumulator **verifies**. So the folded path is confirmed on a real SLH-DSA signature, not just synthetic all-zeros. Per-step timing matches the synthetic run within ≈±20% load variance.

**Multi-step at production params hits the 24 GB memory ceiling.** Folding the 7 real per-layer witnesses into the production accumulator (`c_data_entries = κ×D = 972`, `child_count = 14`, `r_len = 26` — surfaced and fixed via the `PostParentShapeMismatch` probe) parses, sat-checks all 7, builds the plan, and preprocesses cleanly — but the append/fold phase exceeds memory. Even a 2-step chain peaked at **14.24 GB RSS / 130 GB committed footprint** before a macOS memory-pressure kill; the 7-step was SIGKILLed. The single-step (`c=2`) path fits at 10.46 GB, and the `c=972` accumulator *does* complete on the tiny 440-R1CS smoke circuit (9.99 GB) — it's the 486K-R1CS HT-layer step shell (30M F' rows) that doesn't fit. **The full multi-step real chain needs a 32 GB+ box**; the `~815 s` full-chain figure stays a per-step projection. (The multi-witness machinery and shapes are correct — it dies in the memory-heavy fold, not on any shape/correctness check.)

Folded is ~50× slower per-step than Row-1 monolithic in prover wall-clock; per-step RSS is ~2× monolithic.

### Reading the three rows — what each comparison isolates

The gap between Row 1 and Row 2 isolates the *stack* contribution — secq256r1 + Hyrax → Goldilocks + Hash-MLE at the same monolithic strategy. Note this conflates **field and PCS** (both change between the rows); it is *not* a pure-field comparison (see Row 2's attribution caveat). The gap between Row 2 and Row 3 isolates the *folding-scheme* contribution at the same field + Poseidon family. **Status**: Rows 1 and 2 are fully measured end-to-end (real witnesses, verify passes). Row 3 is confirmed on a **real signature layer** for one HT-layer fold step (verify passes); the full multi-step real chain at `c=972` is **memory-bound on this 24 GB box** (OOM in the fold phase, needs 32 GB+), so its full-chain total stays a per-step projection. The closing SNARK is blocked upstream (`Decider(Unsupported)` at Nightstream 755c1595). Net: Rows 1↔2 are a finished comparison; Row 3's single-step folding cost is real-witness-measured, its full-chain total is projected and the finisher is unmeasured.

Side Note:
- load pk: 4281 ms
- prep_prove: 20 ms

## Run it

### 1. Clone

```sh
git clone https://github.com/moven0831/slh-dsa-128s-poseidon-bench.git
cd slh-dsa-128s-poseidon-bench
git checkout feat/slh-dsa-spartan2-bench
```

### 2a. Row 1 — secq256r1 monolithic

Compile the secq256r1 circuit:

```sh
cd wallet-unit-poc/circom
corepack enable && yarn install
yarn compile:slh_dsa_1k
```

Verify: `npx circomkit info slh_dsa_128s_poseidon_1k` → **Constraints: 3992159**.

Build + run the prover:

```sh
cd ../slh-dsa-spartan2
cargo build --release
/usr/bin/time -l ./target/release/slh-dsa-spartan2 setup
/usr/bin/time -l ./target/release/slh-dsa-spartan2 prove --input ../circom/inputs/slh_dsa/1k/default.json
/usr/bin/time -l ./target/release/slh-dsa-spartan2 verify
```

Regenerate the witness inputs (deterministic from fixed seeds, secq256r1-only):

```sh
git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit
FORK_INPUTS=../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k \
  bash scripts/regen_slh_dsa_input.sh
```

Source: [`scripts/poseidon_sign.mjs`](https://github.com/moven0831/slh-dsa-circuit/blob/main/scripts/poseidon_sign.mjs).

### 2b. Row 2 — Goldilocks monolithic

Compile the Goldilocks circuit (in the [`slh-dsa-circuit`](https://github.com/moven0831/slh-dsa-circuit) repo, ~2 min on 24 GB):

```sh
cd ../slh-dsa-circuit
corepack enable && yarn install && bash scripts/vendor.sh
bash scripts/build_main_poseidon_gl.sh
```

Produces `build/main_poseidon_gl/main_poseidon_gl.r1cs` (446 MB) plus the WASM
witness calculator under `build/main_poseidon_gl/main_poseidon_gl_js/`.

Generate a real witness with the Rust Goldilocks signer (in the
[`slh-dsa-neo`](https://github.com/moven0831/slh-dsa-neo) repo), then run the
circom WASM calculator on its input JSON:

```sh
cd ../slh-dsa-neo
cargo run --release -p slh-poseidon-gl --features cli -- \
  emit-monolithic --seed 0 --out /tmp/main_poseidon_gl_input.json
cd ../slh-dsa-circuit/build/main_poseidon_gl/main_poseidon_gl_js
NODE_OPTIONS="--max-old-space-size=12288" \
  node generate_witness.js main_poseidon_gl.wasm \
    /tmp/main_poseidon_gl_input.json /tmp/main_poseidon_gl.wtns
# generate_witness.js exits 0 iff the signature verifies (the circuit's
# `xmss_root === pk_root` asserts fire on a bad signature).
```

Build + run the Goldilocks Spartan2-GL prover end-to-end:

```sh
cd ../../../../slh-dsa-128s-poseidon-bench/wallet-unit-poc/slh-dsa-spartan2-gl
cargo build --release
R1CS=../../../slh-dsa-circuit/build/main_poseidon_gl/main_poseidon_gl.r1cs
# setup only (no witness):
/usr/bin/time -l ./target/release/slh-dsa-spartan2-gl setup --r1cs "$R1CS"
# full pipeline (setup + prove + verify + sizes), needs the .wtns:
RUST_LOG=warn /usr/bin/time -l \
  ./target/release/slh-dsa-spartan2-gl benchmark --r1cs "$R1CS" --wtns /tmp/main_poseidon_gl.wtns
```
