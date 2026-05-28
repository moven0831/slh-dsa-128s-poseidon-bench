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

`main_poseidon_gl.circom` (Plonky2 v1.1.0 Goldilocks Poseidon t=12, 30 rounds, x⁷ S-box), **3,692,597 R1CS / 3,558,276 wires / 1 public output / 8,912 private inputs**.

| Phase   |       Time | Peak RSS |  Artifact     |     Size |
| ------- | ---------: | -------: | ------------- | -------: |
| Setup   |  12,956 ms |  4.43 GB | Proving key   |    *TBD* |
| Witness |    *TBD*   |        – | Verifying key |    *TBD* |
| Prove   |    *TBD*   |   *TBD*  | **Proof**     |  *TBD*   |
| Verify  |    *TBD*   |   *TBD*  | R1CS          |  446 MB  |

Setup-phase only (no witness gen, no prove, no verify yet): **~1.7× faster** setup and **~2.4× less RSS** than secq256r1's setup at the same scale. Goldilocks R1CS is **92.5%** of the secq256r1 size (3.69M vs 3.99M). **Do not read this as a 1.7× end-to-end win** — Row 1's setup is also faster than its prove. Wait for the prove/verify rows below before drawing whole-pipeline conclusions.

`Prove`/`verify` numbers are pending a Goldilocks-Poseidon-aware witness generator. The existing [`scripts/poseidon_sign.mjs`](https://github.com/moven0831/slh-dsa-circuit/blob/main/scripts/poseidon_sign.mjs) is secq256r1-only; either adapt it to Plonky2 v1.1.0 Goldilocks constants (~1 day) or wait for the Rust signer in [`slh-dsa-neo/crates/slh-poseidon-gl`](https://github.com/moven0831/slh-dsa-neo/tree/main/crates/slh-poseidon-gl) (T1.1.c, multi-day).

### Row 3 — Goldilocks D4 folded ([`slh-dsa-neo`](https://github.com/moven0831/slh-dsa-neo))

Nightstream `r1cs_f_prime` over the same Goldilocks Poseidon family, per-XMSS-layer D4 fold of `bench_ht_layer_gl.circom` (485,930 R1CS / 467,721 wires per step). See [`slh-dsa-neo/MEMO.md`](https://github.com/moven0831/slh-dsa-neo/blob/main/MEMO.md) for the full breakdown.

| Path           | Prove (full chain) | Verify | Peak RSS | Proof              |
| -------------- | -----------------: | -----: | -------: | ------------------ |
| 1-step, c=2    |        2.07 s      | 0.62 s |  2.26 GB | uncompressed       |
| 1-step, c=972 (extrap.) |       ~116 s |      – |       – | uncompressed       |
| 7-step chain (extrap.)  |       ~815 s | ~20 s  | 10.5 GB per step | uncompressed |
| 7-step + Spartan2-GL final SNARK | *blocked* | – | – | *Decider(Unsupported) at Nightstream 755c1595 — see MEMO.md* |

Folded is ~50× slower per-step than Row-1 monolithic in prover wall-clock; per-step RSS is ~2× monolithic but doesn't compound across folds (the IVC property).

### Reading the three rows — what each comparison isolates

The gap between Row 1 and Row 2, once Row 2's prove/verify numbers land, will isolate the *field* contribution (secq256r1 → Goldilocks at the same monolithic strategy). The gap between Row 2 and Row 3 isolates the *folding-scheme* contribution at the same field. **Currently incomplete**: Row 2 has only setup measured; Row 3's full-chain and finisher rows are extrapolated or blocked. Treat this section as a measurement plan, not a finished comparison.

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

Produces `build/main_poseidon_gl/main_poseidon_gl.r1cs` (446 MB).

Build + run the Goldilocks Spartan2-GL prover:

```sh
cd ../slh-dsa-128s-poseidon-bench/wallet-unit-poc/slh-dsa-spartan2-gl
cargo build --release
# Setup needs only the .r1cs:
/usr/bin/time -l ./target/release/slh-dsa-spartan2-gl setup --r1cs ../../../slh-dsa-circuit/build/main_poseidon_gl/main_poseidon_gl.r1cs
# Prove/verify needs a Goldilocks-Poseidon .wtns (see witness gap above):
# /usr/bin/time -l ./target/release/slh-dsa-spartan2-gl benchmark --r1cs … --wtns …
```
