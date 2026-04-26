# Show-circuit benchmarks

Looking for results? See [`REPORT.md`](./REPORT.md) for the combined Markdown report (constraints + timings + sizes + Mermaid charts + takeaways), regenerated from the per-suite outputs by `yarn bench:report`.

Two benchmark suites driven by a single source of truth: [`configs.json`](./configs.json).

| Side | What it measures | Where |
| --- | --- | --- |
| **circom** | R1CS constraint counts, wires, labels | `circom/benchmarks/results/constraints.md` |
| **ecdsa-spartan2** | setup / witness-gen / prove / reblind / verify timings; PK/VK/proof sizes | `ecdsa-spartan2/benchmarks/results/show-timings.md` |

Each entry in `configs.json` is compiled as `Show(nClaims, maxPredicates, maxLogicTokens, 64)`. `predicateLen` and `exprLen` equal `maxPredicates` and `maxLogicTokens` respectively, so the circuit is sized exactly to its workload, with no padding.

## Sweeps

| Sweep | Variable | Held fixed | Purpose |
| --- | --- | --- | --- |
| `predicates_at_n10` | `m ∈ {1, 2, 4, 8}` (and the matching left-deep AND chain `t = 2m - 1`) | `n = 10` | Cost-per-predicate. |
| `claims_at_m1` | `n ∈ {1, 5, 10, 20, 30}` | `m = 1, t = 1` | Cost-per-claim slot (claim multiplexer + signature path). |
| `operator_mix` | `predicateOp ∈ {==, ≤}` | `n = 10, m = 4, t = 7` | `==` vs `≤` (range-check) cost. |
| `rhs_kind` | RHS kind (literal vs claim-reference) | `n = 10, m = 4, t = 7` | Constant operand vs claim-to-claim comparison. |

Constraint counts for `operator_mix` and `rhs_kind` will match `S1_m4_n10`, since the circuit handles all operators and RHS modes uniformly. Differences for those sweeps will only show up in witness generation and proving timings.

## 1) Constraint counts (circom)

```sh
cd circom
yarn install                      # once
npx ts-node scripts/benchmarks/run-constraints.ts
```

Each config writes a small main file under `circuits/_bench_main/<name>.circom`, compiles it via `circom -p secq256r1 --O2 --r1cs --sym`, then parses `snarkjs r1cs info`. Output: `circom/benchmarks/results/constraints.{md,csv}`.

## 2) Timings (ecdsa-spartan2)

The driver patches `circom/circuits.json`'s `show` entry per config, recompiles the circuit, rebuilds the `bench_show` binary so `witnesscalc-adapter` re-links the new `show.cpp`, then times one full pipeline (setup → witness → prove → reblind → verify) per config. `circuits.json` is backed up before the run and restored on exit, including on Ctrl-C or error.

Prerequisite: the existing prepare/show keys must already be set up at least once for the configured `circuit_size`, since the build pipeline needs the JWT/Show witness toolchain wired up. From a fresh checkout that means following the standard `ecdsa-spartan2/README.md` setup once first.

Run all configs:

```sh
cd ecdsa-spartan2
./benchmarks/scripts/run-show-bench.sh
```

Run a subset (names from `configs.json`):

```sh
./benchmarks/scripts/run-show-bench.sh S1_m1_n10 S1_m8_n10 S2_n30_m1
```

Each config takes roughly the time of one `yarn compile:show` + one incremental `cargo build --release` + one `bench_show` invocation. The first run of the day is slowest because witnesscalc rebuilds for the new `show.cpp`; subsequent runs are seconds plus the actual prove/reblind cost.

## What the spartan2 binary measures

`ecdsa-spartan2/src/bin/bench_show.rs` runs the Show pipeline in-memory (no key/proof files written under `keys/`). It uses a standalone `BenchShowCircuit` whose `shared` layout matches the production split-R1CS (`[deviceKeyX, deviceKeyY, claimValues[..n]]`), so reblind cost reflects what a real presentation would pay.

Outputs per config:

```jsonc
{
  "name": "S1_m4_n10",
  "n_claims": 10,
  "timings_ms": { "setup": 1234, "witness_gen": 12, "prove": 80, "reblind": 30, "verify": 25 },
  "sizes_bytes": { "proving_key": 3194880, "verifying_key": 4112, "proof": 41502, "reblinded_proof": 41502, "witness": 109152 },
  "expression_result": true
}
```

`witness_gen` is timed before `prove` (the witness is cached on the circuit so it isn't recomputed inside `prove`); `prove` is therefore proving-only.

## Files

```
circom/
├── benchmarks/
│   ├── configs.json                      # source of truth for both suites
│   ├── README.md                         # this file
│   └── results/
│       ├── constraints.md
│       └── constraints.csv
└── scripts/benchmarks/
    ├── run-constraints.ts                # circom side
    └── generate-show-input.ts            # input JSON generator (called by orchestrator)

ecdsa-spartan2/
├── benchmarks/
│   ├── scripts/run-show-bench.sh         # orchestrator
│   └── results/
│       ├── <config-name>.json            # per-config raw output
│       ├── show-timings.md               # aggregated table
│       └── show-timings.csv              # aggregated CSV
└── src/bin/bench_show.rs                 # timing binary
```

## Adding a config

Append to `configs.json`. Required fields:

```jsonc
{
  "name": "MY_TEST",                      // used as filename + label
  "sweep": "my_sweep",                    // groups rows in the result tables
  "nClaims": 10,                          // = template param 1
  "maxPredicates": 2,                     // = template param 2 (= predicateLen at runtime)
  "maxLogicTokens": 3,                    // = template param 3 (= exprLen at runtime)
  "expression": ["P0", "P1", "AND"],      // postfix tokens; length must equal maxLogicTokens
  "predicateOp": "le",                    // "le" | "ge" | "eq"
  "rhsIsRef": false                       // false: literal RHS; true: claim-to-claim comparison
}
```

Both suites pick up the new entry on the next run, no further code changes needed.
