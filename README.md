# SLH-DSA-128s (Poseidon, 1 KB) — Spartan2 benchmark

End-to-end prove + verify numbers for the [SLH-DSA-128s Poseidon-hash verifier](https://github.com/moven0831/slh-dsa-circuit/blob/main/circuits/main_poseidon.circom) on the **same Spartan2 stack** as [`wallet-unit-poc/ecdsa-spartan2`](wallet-unit-poc/ecdsa-spartan2): `T256HyraxEngine` / Hyrax-PC over secq256r1.

This fork adds [`wallet-unit-poc/slh-dsa-spartan2`](wallet-unit-poc/slh-dsa-spartan2) and vendors the circuit into `wallet-unit-poc/circom/circuits/slh_dsa/`. Rest is upstream [`privacy-ethereum/zkID`](https://github.com/privacy-ethereum/zkID)@`3d325e3`.

## Results (M3 / 24 GB)

| Phase   |       Time | Peak RSS |  Artifact     |     Size |
| ------- | ---------: | -------: | ------------- | -------: |
| Setup   |  23,143 ms | 10.45 GB | Proving key   |  2.37 GB |
| Witness |  ~10,000 ms |        – | Verifying key |  2.37 GB |
| Prove   |  16,184 ms |  5.41 GB | **Proof**     | **208.8 KB** |
| Verify  |   9,522 ms |  3.11 GB | R1CS          |  2.28 GB |

**3,992,159 R1CS constraints** · 3,861,768 wires · 1,056 public / 7,856 private inputs.

vs `ecdsa-spartan2 jwt_1k` (M5/24 GB): ~10–14× slower prove/verify, ~9× larger PK, ~3× larger proof — tracks the R1CS-size ratio (4 M vs ~500 K). VK matches PK because this Spartan2 fork's `VerifierKey` serializes the full preprocessed shape `S`; the on-wire artifact is the 208 KB proof.

## Run it

### Prereqs

- ≥ 24 GB RAM (setup peaks ~10.5 GB; PK is 2.37 GB)
- Rust 1.75+, Node 20+, Yarn 4 (`corepack enable`), clang/g++, make
- macOS: `brew install gmp nlohmann-json`

### 1. Clone

```sh
git clone https://github.com/moven0831/slh-dsa-128s-poseidon-bench.git
cd slh-dsa-128s-poseidon-bench
git checkout feat/slh-dsa-spartan2-bench
```

### 2. Compile circuit (~1 min)

```sh
cd wallet-unit-poc/circom
corepack enable && yarn install
yarn compile:slh_dsa_1k
```

Verify: `npx circomkit info slh_dsa_128s_poseidon_1k` → **Constraints: 3992159**.

### 3. Build prover (~15 min cold)

```sh
cd ../slh-dsa-spartan2
cargo build --release
```

`witnesscalc-adapter` compiles a 30 MB `.cpp` witness generator into a static lib; `build.rs` embeds an `rpath` for the dylib.

### 4. Run

Witness fixture `wallet-unit-poc/circom/inputs/slh_dsa/1k/default.json` is checked in.

```sh
/usr/bin/time -l ./target/release/slh-dsa-spartan2 setup
/usr/bin/time -l ./target/release/slh-dsa-spartan2 prove --input ../circom/inputs/slh_dsa/1k/default.json
/usr/bin/time -l ./target/release/slh-dsa-spartan2 verify   # → VERIFY OK
```

### Regenerate the witness (optional, ~22 min)

Signer lives in the source repo:

```sh
git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit
FORK_INPUTS=../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k \
  bash scripts/regen_slh_dsa_input.sh
```

Deterministic from fixed seeds. Source: [`scripts/poseidon_sign.mjs`](https://github.com/moven0831/slh-dsa-circuit/blob/main/scripts/poseidon_sign.mjs).

## Diff vs upstream

| Path | Change |
| --- | --- |
| `wallet-unit-poc/circom/circuits/slh_dsa/` | New: vendored from [moven0831/slh-dsa-circuit](https://github.com/moven0831/slh-dsa-circuit) |
| `wallet-unit-poc/circom/{circuits.json,package.json,scripts/compile.sh}` | Added `slh_dsa_128s_poseidon_1k` entry/script/case |
| `wallet-unit-poc/circom/inputs/slh_dsa/1k/default.json` | New: 50 KB witness fixture |
| `wallet-unit-poc/slh-dsa-spartan2/` | New crate (single-circuit; no prepare/show/reblind/mdoc) |

## Caveats

- **Non-standard Poseidon-SLH-DSA.** circomlib's BN254 constants reused over secq256r1: R1CS structure unchanged, but **security analysis does NOT transfer**. See [upstream](https://github.com/moven0831/slh-dsa-circuit).
- Signer is a fixture generator, not a production primitive.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Assert Failed. Error in template HtVerify_336 line: 96` at witness gen | Stale fixture — regenerate (see above). |
| `Library not loaded: @rpath/libwitnesscalc_slh_dsa_128s_poseidon_1k.dylib` | `cargo clean -p slh-dsa-spartan2 && cargo build --release`. |
| `setup` OOMs on 24 GB | Close other apps; macOS may SIGKILL before 10.5 GB if pressure is high. |
| `gmp not found` at link | `brew install gmp` / `apt install libgmp-dev`. |

## Related

- Circuit + signer: <https://github.com/moven0831/slh-dsa-circuit>
- Spartan2 fork: <https://github.com/0xVikasRushi/Spartan2>, branch `openac-sdk`
- circom-scotia fork: <https://github.com/0xVikasRushi/circom-scotia>, branch `feat/spartan2`
- witnesscalc-adapter: <https://github.com/zkmopro/witnesscalc_adapter>, branch `secq256r1-support`

---

## About zkID (upstream)

zkID is a team within Privacy Stewards of Ethereum (PSE) at the Ethereum Foundation, advancing Zero Knowledge Proofs in digital identity. See [pse.dev](https://pse.dev/projects/zk-id), the [roadmap](https://pse-team.notion.site/zkID-2026-Roadmap-2fdd57e8dd7e80f48a37c24e9fbe09d6), and upstream benchmarks at [csp-benchmarks](https://github.com/privacy-ethereum/csp-benchmarks).
