#!/usr/bin/env bash
#
# Driver for the Show-circuit timing benchmarks.
#
# For each entry in `circom/benchmarks/configs.json`:
#   1. Patch `circom/circuits.json` "show" entry to `[nClaims, maxPredicates, maxLogicTokens, valueBits]`.
#   2. Run `yarn compile:show` (regenerates `show.r1cs` + `show.cpp/.dat`).
#   3. Generate a tailored Show input JSON.
#   4. `cargo build --release --bin bench_show` (picks up the new witness generator).
#   5. `cargo run --release --bin bench_show` to time setup → prove → reblind → verify.
#
# Per-config JSON results land in `ecdsa-spartan2/benchmarks/results/<name>.json`.
# A combined Markdown summary lands in `ecdsa-spartan2/benchmarks/results/show-timings.md`.
#
# `circuits.json` is backed up before the run and restored on exit (including Ctrl-C / errors).
#
# Run from anywhere; paths are resolved relative to the script.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WALLET_DIR="$(cd -- "$ROOT_DIR/.." && pwd)"
CIRCOM_DIR="$WALLET_DIR/circom"
SPARTAN_DIR="$WALLET_DIR/ecdsa-spartan2"

CONFIGS_PATH="$CIRCOM_DIR/benchmarks/configs.json"
CIRCUITS_JSON="$CIRCOM_DIR/circuits.json"
INPUT_DIR="$CIRCOM_DIR/benchmarks/inputs"
RESULTS_DIR="$SPARTAN_DIR/benchmarks/results"

mkdir -p "$INPUT_DIR" "$RESULTS_DIR"

# Restore circuits.json on exit so a failed run never leaves the repo in a
# half-patched state.
BACKUP_PATH="$(mktemp -t circuits.json.XXXXXX)"
cp "$CIRCUITS_JSON" "$BACKUP_PATH"
restore() {
  if [[ -f "$BACKUP_PATH" ]]; then
    cp "$BACKUP_PATH" "$CIRCUITS_JSON"
    rm -f "$BACKUP_PATH"
    echo "[bench] restored $CIRCUITS_JSON" >&2
  fi
}
trap restore EXIT INT TERM

# Optional filter: pass one or more config names on the CLI to run a subset.
SELECT=("$@")

names=$(node -e '
  const cfg = require(process.argv[1]);
  console.log(cfg.configs.map(c => c.name).join("\n"));
' "$CONFIGS_PATH")

if [[ ${#SELECT[@]} -gt 0 ]]; then
  filtered=""
  for n in $names; do
    for s in "${SELECT[@]}"; do
      if [[ "$n" == "$s" ]]; then filtered+="$n"$'\n'; fi
    done
  done
  names="$(printf '%s' "$filtered")"
fi

echo "[bench] running configs:"
printf '  - %s\n' $names

for name in $names; do
  echo
  echo "════════════════════════════════════════════════════════════"
  echo "  [$name]"
  echo "════════════════════════════════════════════════════════════"

  # Pull this config's params out of configs.json.
  read -r N_CLAIMS M_PREDS T_TOKENS VALUE_BITS <<<"$(node -e '
    const fs = require("fs");
    const cfg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const c = cfg.configs.find(x => x.name === process.argv[2]);
    if (!c) { console.error("config not found:", process.argv[2]); process.exit(1); }
    process.stdout.write([c.nClaims, c.maxPredicates, c.maxLogicTokens, cfg.valueBits].join(" "));
  ' "$CONFIGS_PATH" "$name")"

  echo "[bench] params: nClaims=$N_CLAIMS maxPredicates=$M_PREDS maxLogicTokens=$T_TOKENS valueBits=$VALUE_BITS"

  # 1) Patch circuits.json so circomkit instantiates Show with the right params.
  node -e '
    const fs = require("fs");
    const path = process.argv[1];
    const params = process.argv.slice(2).map(Number);
    const j = JSON.parse(fs.readFileSync(path, "utf8"));
    j.show.params = params;
    fs.writeFileSync(path, JSON.stringify(j, null, 2) + "\n");
  ' "$CIRCUITS_JSON" "$N_CLAIMS" "$M_PREDS" "$T_TOKENS" "$VALUE_BITS"

  # 2) Recompile show (regenerates .r1cs + .cpp + copies to build/cpp/).
  echo "[bench] compiling show with $(jq -r '.show.params | tostring' "$CIRCUITS_JSON" 2>/dev/null || echo "[$N_CLAIMS, $M_PREDS, $T_TOKENS, $VALUE_BITS]") ..."
  ( cd "$CIRCOM_DIR" && yarn compile:show ) >/dev/null

  # 3) Build a Show input JSON tailored to this config.
  INPUT_JSON="$INPUT_DIR/$name.json"
  ( cd "$CIRCOM_DIR" && npx ts-node scripts/benchmarks/generate-show-input.ts "$name" "$INPUT_JSON" ) >/dev/null

  # 4) Rebuild bench_show; build.rs re-links witnesscalc when show.cpp changes.
  ( cd "$SPARTAN_DIR" && cargo build --release --bin bench_show ) >/dev/null

  # 5) Time the pipeline.
  RESULT_JSON="$RESULTS_DIR/$name.json"
  ( cd "$SPARTAN_DIR" && cargo run --release --bin bench_show -- \
      --name "$name" \
      --n-claims "$N_CLAIMS" \
      --input "$INPUT_JSON" \
      --output "$RESULT_JSON" )
done

# Aggregate per-config result JSONs into a Markdown + CSV table.
node -e '
  const fs = require("fs");
  const path = require("path");
  const cfg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const resultsDir = process.argv[2];

  const rows = [];
  for (const c of cfg.configs) {
    const p = path.join(resultsDir, `${c.name}.json`);
    if (!fs.existsSync(p)) continue;
    const r = JSON.parse(fs.readFileSync(p, "utf8"));
    rows.push({ config: c, result: r });
  }

  const fmtKb = (b) => `${(b / 1024).toFixed(2)} KB`;
  const fmtMb = (b) => `${(b / (1024 * 1024)).toFixed(2)} MB`;

  const groups = new Map();
  for (const row of rows) {
    if (!groups.has(row.config.sweep)) groups.set(row.config.sweep, []);
    groups.get(row.config.sweep).push(row);
  }

  const lines = [];
  lines.push("# Show circuit: proving / reblind / verify timings");
  lines.push("");
  lines.push("Generated by `benchmarks/scripts/run-show-bench.sh`. Each row is a separate compilation of `Show(nClaims, maxPredicates, maxLogicTokens, 64)`. Timings are wall clock, in milliseconds. Sizes are bincode-serialized byte counts of the in-memory artifacts.");
  lines.push("");
  for (const [sweep, gr] of groups) {
    lines.push(`## Sweep: \`${sweep}\``);
    lines.push("");
    lines.push("| name | n | m | t | op | rhsRef | setup ms | witness ms | prove ms | reblind ms | verify ms | proof | reblinded | pk | vk |");
    lines.push("| --- | ---: | ---: | ---: | --- | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (const { config, result } of gr) {
      const t = result.timings_ms; const s = result.sizes_bytes;
      lines.push(
        `| ${config.name} | ${config.nClaims} | ${config.maxPredicates} | ${config.maxLogicTokens} | ${config.predicateOp} | ${config.rhsIsRef ? "yes" : "no"} | ${t.setup} | ${t.witness_gen} | ${t.prove} | ${t.reblind} | ${t.verify} | ${fmtKb(s.proof)} | ${fmtKb(s.reblinded_proof)} | ${fmtMb(s.proving_key)} | ${fmtKb(s.verifying_key)} |`
      );
    }
    lines.push("");
  }

  fs.writeFileSync(path.join(resultsDir, "show-timings.md"), lines.join("\n"));

  console.log("\n" + lines.join("\n"));
  console.log(`\nWrote ${path.join(resultsDir, "show-timings.md")}`);
' "$CONFIGS_PATH" "$RESULTS_DIR"
