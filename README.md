# SLH-DSA-128s with Poseidon Hash, OpenAC benchmark

End-to-end prove + verify numbers for the [SLH-DSA-128s Poseidon-hash verifier](https://github.com/moven0831/slh-dsa-circuit/blob/main/circuits/main_poseidon.circom) on the **same Spartan2 stack** as [`wallet-unit-poc/ecdsa-spartan2`](wallet-unit-poc/ecdsa-spartan2): `T256HyraxEngine` / Hyrax-PC over secq256r1 that current OpenAC used.

This fork adds [`wallet-unit-poc/slh-dsa-spartan2`](wallet-unit-poc/slh-dsa-spartan2) and vendors the circuit into `wallet-unit-poc/circom/circuits/slh_dsa/`. Rest is upstream [`privacy-ethereum/zkID`](https://github.com/privacy-ethereum/zkID)@`3d325e3`.

## Results (M3 / 24 GB)

| Phase   |       Time | Peak RSS |  Artifact     |     Size |
| ------- | ---------: | -------: | ------------- | -------: |
| Setup   |  23,143 ms | 10.45 GB | Proving key   |  2.37 GB |
| Witness |  1387 ms   |        – | Verifying key |  2.37 GB |
| Prove   |  16,184 ms |  5.41 GB | **Proof**     | **208.8 KB** |
| Verify  |   9,522 ms |  3.11 GB | R1CS          |  2.28 GB |

**3,992,159 R1CS constraints** · 3,861,768 wires · 1,056 public / 7,856 private inputs.

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

### 2. Compile circuit

```sh
cd wallet-unit-poc/circom
corepack enable && yarn install
yarn compile:slh_dsa_1k
```

Verify: `npx circomkit info slh_dsa_128s_poseidon_1k` → **Constraints: 3992159**.

### 3. Build prover

```sh
cd ../slh-dsa-spartan2
cargo build --release
```

### 4. Run

Go to `./wallet-unit-poc/slh-dsa-spartan2`

```sh
/usr/bin/time -l ./target/release/slh-dsa-spartan2 setup
/usr/bin/time -l ./target/release/slh-dsa-spartan2 prove --input ../circom/inputs/slh_dsa/1k/default.json
/usr/bin/time -l ./target/release/slh-dsa-spartan2 verify
```

### Regenerate the witness

Signer lives in the source repo:

```sh
git clone https://github.com/moven0831/slh-dsa-circuit.git
cd slh-dsa-circuit
FORK_INPUTS=../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k \
  bash scripts/regen_slh_dsa_input.sh
```

Deterministic from fixed seeds. Source: [`scripts/poseidon_sign.mjs`](https://github.com/moven0831/slh-dsa-circuit/blob/main/scripts/poseidon_sign.mjs).
