# SLH-DSA-128s (Poseidon, 1 KB) — Spartan2 benchmark

End-to-end **prove + verify** numbers for the [SLH-DSA-128s Poseidon-hash signature verifier](https://github.com/moven0831/slh-dsa-circuit/blob/main/circuits/main_poseidon.circom) on **the same Spartan2 stack** that [`wallet-unit-poc/ecdsa-spartan2`](wallet-unit-poc/ecdsa-spartan2) uses for its JWT/ECDSA prepare-stage benchmark. Same backend (`T256HyraxEngine` / Hyrax-PC over secq256r1), same hardware, → directly comparable.

This fork adds a single new Rust crate, [`wallet-unit-poc/slh-dsa-spartan2`](wallet-unit-poc/slh-dsa-spartan2), and vendors the verifier circuit into `wallet-unit-poc/circom/circuits/slh_dsa/`. Everything else is upstream [`privacy-ethereum/zkID`](https://github.com/privacy-ethereum/zkID) at commit `3d325e3`.

## Results (M3 / 24 GB)

| Phase   |       Time | Peak RSS |  Artifact     |     Size |
| ------- | ---------: | -------: | ------------- | -------: |
| Setup   |  23,143 ms | 10.45 GB | Proving key   |  2.37 GB |
| Witness |  ~10,000 ms |        – | Verifying key |  2.37 GB |
| Prove   |  16,184 ms |  5.41 GB | **Proof**     | **208.8 KB** |
| Verify  |   9,522 ms |  3.11 GB | R1CS          |  2.28 GB |

Circuit: **3,992,159 R1CS constraints**, 3,861,768 wires, 1,056 public inputs (`pk[32]`, `msg[1024]`), 7,856 private inputs.

vs sibling `ecdsa-spartan2 jwt_1k` (M5/24 GB per its README): Prove 1.12 s, Verify 0.74 s, PK 257 MB, Proof 76 KB. SLH-DSA is ~10–14× slower on prove/verify, ~9× larger PK, ~3× larger proof — tracks the R1CS-size ratio (4 M vs ~500 K constraints).

> **VK size matches PK** because this Spartan2 fork's `VerifierKey` serializes the full preprocessed R1CS shape `S`. The on-wire artifact is the 208 KB proof.

## How to run the benchmark

### Prerequisites

- **Hardware**: Apple Silicon or x86-64 with **≥ 24 GB RAM**. Setup peaks at ~10.5 GB RSS; the proving key is 2.37 GB on disk. On a fully-loaded 24 GB host, close other apps before `setup`.
- **Toolchain**:
  - Rust 1.75+ (stable)
  - Node.js 20+
  - Yarn 4 (enable via `corepack enable`)
  - clang/g++ + make (for `witnesscalc-adapter`'s C++ build)
  - macOS: `brew install gmp nlohmann-json` (gmp needed at link time)

### 1. Clone this branch

```sh
git clone https://github.com/moven0831/slh-dsa-128s-poseidon-bench.git
cd slh-dsa-128s-poseidon-bench
git checkout feat/slh-dsa-spartan2-bench
```

### 2. Compile the Circom circuit (~1 min, < 2 GB RSS)

```sh
cd wallet-unit-poc/circom
corepack enable
yarn install
yarn compile:slh_dsa_1k
```

This produces:
- `build/slh_dsa_128s_poseidon_1k/slh_dsa_128s_poseidon_1k.r1cs` (2.28 GB) — consumed by `circom-scotia`
- `build/cpp/slh_dsa_128s_poseidon_1k.{cpp,dat}` — consumed by `witnesscalc-adapter`

Sanity check: `npx circomkit info slh_dsa_128s_poseidon_1k` should report **Number of Constraints: 3992159**.

### 3. Build the Spartan2 prover crate (~15 min cold, seconds incremental)

```sh
cd ../slh-dsa-spartan2
cargo build --release
```

The first build is slow because `witnesscalc-adapter` compiles the 30 MB `.cpp` witness generator into a static library. On macOS, the build script also embeds an `rpath` so the linked `libwitnesscalc_slh_dsa_128s_poseidon_1k.dylib` resolves at runtime without `DYLD_LIBRARY_PATH`.

### 4. Witness fixture

The witness fixture `wallet-unit-poc/circom/inputs/slh_dsa/1k/default.json` is already checked in — no signer run is needed to reproduce the numbers below. To regenerate the fixture from scratch, see [§ Regenerating the witness fixture](#regenerating-the-witness-fixture).

### 5. Setup → Prove → Verify

```sh
# One-time setup: produces keys/slh_dsa_1k_{pk,vk}.key (2.37 GB each)
./target/release/slh-dsa-spartan2 setup

# Prove against the checked-in witness
./target/release/slh-dsa-spartan2 prove \
    --input ../circom/inputs/slh_dsa/1k/default.json

# Verify
./target/release/slh-dsa-spartan2 verify
# → VERIFY OK
```

To capture peak RSS (matches the table above):

```sh
/usr/bin/time -l ./target/release/slh-dsa-spartan2 setup
/usr/bin/time -l ./target/release/slh-dsa-spartan2 prove --input ../circom/inputs/slh_dsa/1k/default.json
/usr/bin/time -l ./target/release/slh-dsa-spartan2 verify
```

The CLI prints per-phase timings + artifact sizes after each command. Wall times include file I/O of the 2.37 GB proving / verifying keys.

### Regenerating the witness fixture

The Poseidon-SLH-DSA-128s scheme is non-standard (circomlib BN254 Poseidon constants reused over circom's secq256r1, which empirically equals secp256r1's base field). No existing crypto library implements signing under this scheme, so the witness is produced by a JS signer in the source repo.

```sh
# In a separate clone of the source repo:
git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit
FORK_INPUTS=../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k \
  bash scripts/regen_slh_dsa_input.sh
```

Runtime: **~22 min** in JS BigInt arithmetic on M3. The script deterministically derives `sk_seed`/`pk_seed`/`msg`/`r` from fixed labels for reproducibility. Source: [`scripts/poseidon_sign.mjs`](https://github.com/moven0831/slh-dsa-circuit/blob/main/scripts/poseidon_sign.mjs).

## What this fork changes vs upstream

| Path | Change |
| --- | --- |
| `wallet-unit-poc/circom/circuits/slh_dsa/` | New: vendored circuit (`main_poseidon.circom` + `common/` + `poseidon/` from [moven0831/slh-dsa-circuit](https://github.com/moven0831/slh-dsa-circuit)) |
| `wallet-unit-poc/circom/circuits.json` | Added `slh_dsa_128s_poseidon_1k` entry |
| `wallet-unit-poc/circom/package.json` | Added `compile:slh_dsa_1k` script |
| `wallet-unit-poc/circom/scripts/compile.sh` | Added `slh_dsa_128s_poseidon_1k` case |
| `wallet-unit-poc/circom/inputs/slh_dsa/1k/default.json` | New: witness fixture (50 KB) |
| `wallet-unit-poc/slh-dsa-spartan2/` | New crate (mirrors `ecdsa-spartan2`, simplified to single-circuit verify) |

The Spartan2 crate is single-circuit: just `setup`, `prove`, `verify`, no `prepare`/`show`/`reblind`/`mdoc` split (SLH-DSA is a signature scheme, no selective-disclosure analog).

## Caveats

- **Poseidon-SLH-DSA-128s is non-standard.** circomlib's BN254-tuned Poseidon constants are reused over secq256r1 — the R1CS structure and constraint count are unchanged from BN254, but the resulting Poseidon instance is not a vetted cryptographic primitive. The benchmark is meaningful for sizing prove/verify cost; **the security analysis does NOT transfer**. See the upstream [Poseidon README](https://github.com/moven0831/slh-dsa-circuit) for the full caveat.
- The included signer is a **fixture generator**, not a production cryptographic signer. It deterministically derives keypair/signature material from fixed seeds.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Error: Assert Failed. Error in template HtVerify_336 line: 96` at witness gen | Witness fixture is stale or for a different prime. Regenerate via [§ Regenerating the witness fixture](#regenerating-the-witness-fixture). |
| `Library not loaded: @rpath/libwitnesscalc_slh_dsa_128s_poseidon_1k.dylib` | `cargo clean -p slh-dsa-spartan2 && cargo build --release`. `build.rs` embeds the rpath at link time. |
| `setup` OOMs on a 24 GB host | Close other apps; peak RSS is ~10.5 GB. On a fully-loaded 24 GB system macOS may SIGKILL before that. 32 GB+ is comfortable. |
| `gmp not found` linker error | `brew install gmp` on macOS; on Linux install `libgmp-dev`. |

## Source repos

- **This fork**: <https://github.com/moven0831/slh-dsa-128s-poseidon-bench> (downstream of `privacy-ethereum/zkID`)
- **Circuit + signer + analysis**: <https://github.com/moven0831/slh-dsa-circuit>
- **Spartan2 fork** (used as dep): <https://github.com/0xVikasRushi/Spartan2>, branch `openac-sdk`
- **circom-scotia fork** (R1CS loader): <https://github.com/0xVikasRushi/circom-scotia>, branch `feat/spartan2`
- **witnesscalc-adapter** (native witness): <https://github.com/zkmopro/witnesscalc_adapter>, branch `secq256r1-support`

---

## About zkID (upstream)

zkID is a team within Privacy Stewards of Ethereum (PSE) at the Ethereum Foundation, focused on advancing the use of Zero Knowledge Proofs (ZKPs) in digital identity systems. We work on research, coordination, education, and development of privacy-preserving, interoperable, and standards-aligned identity infrastructure.

Across the identity ecosystem, we draft technical standards, maintain open-source resources, and prototype infrastructure that aligns with evolving regulatory frameworks. By facilitating collaboration between researchers, developers, governments, and institutions, we bridge foundational cryptographic research with real-world deployment and impact.

For zkID benchmarks, refer to this [repository](https://github.com/privacy-ethereum/csp-benchmarks).

For more information on the zkID team, visit [pse.dev](https://pse.dev/projects/zk-id).

For more details on current tasks and priorities, see the [zkID roadmap](https://pse-team.notion.site/zkID-2026-Roadmap-2fdd57e8dd7e80f48a37c24e9fbe09d6).
