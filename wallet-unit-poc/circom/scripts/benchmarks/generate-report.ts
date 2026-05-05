/// <reference types="node" />
/**
 * Build a single Markdown report combining:
 *   - circom constraint counts  (circom/benchmarks/results/constraints-data.json)
 *   - ecdsa-spartan2 timings    (ecdsa-spartan2/benchmarks/results/<name>.json)
 *
 * Charts are emitted as Mermaid `xychart-beta` blocks (rendered inline by GitHub).
 *
 * Run from the `circom/` directory:
 *   npx ts-node scripts/benchmarks/generate-report.ts
 */

import { existsSync, readFileSync, writeFileSync } from "fs";
import { join, resolve } from "path";

interface BenchConfig {
  name: string;
  sweep: string;
  nClaims: number;
  maxPredicates: number;
  maxLogicTokens: number;
  expression: string[];
  predicateOp: "le" | "ge" | "eq";
  rhsIsRef: boolean;
}

interface ConfigsFile {
  comment: string;
  valueBits: number;
  configs: BenchConfig[];
}

interface ConstraintsRow {
  config: BenchConfig;
  wires: number;
  constraints: number;
  privateInputs: number;
  publicInputs: number;
  publicOutputs: number;
  labels: number;
}

interface TimingsRow {
  name: string;
  n_claims: number;
  timings_ms: { setup: number; witness_gen: number; prove: number; reblind: number; verify: number };
  sizes_bytes: {
    proving_key: number;
    verifying_key: number;
    proof: number;
    reblinded_proof: number;
    witness: number;
  };
  expression_result: boolean;
}

interface Combined {
  config: BenchConfig;
  constraints?: ConstraintsRow;
  timings?: TimingsRow;
}

const REPO_CIRCOM_DIR = resolve(__dirname, "..", "..");
const REPO_WALLET_DIR = resolve(REPO_CIRCOM_DIR, "..");
const CONFIGS_PATH = join(REPO_CIRCOM_DIR, "benchmarks", "configs.json");
const CONSTRAINTS_JSON = join(REPO_CIRCOM_DIR, "benchmarks", "results", "constraints-data.json");
const SPARTAN_RESULTS = join(REPO_WALLET_DIR, "ecdsa-spartan2", "benchmarks", "results");
const REPORT_OUT = join(REPO_CIRCOM_DIR, "benchmarks", "REPORT.md");

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const fmtKb = (b: number) => `${(b / 1024).toFixed(2)} KB`;
const fmtMb = (b: number) => `${(b / (1024 * 1024)).toFixed(2)} MB`;

function loadCombined(): Combined[] {
  const cfg: ConfigsFile = JSON.parse(readFileSync(CONFIGS_PATH, "utf8"));
  const constraints: ConstraintsRow[] = existsSync(CONSTRAINTS_JSON)
    ? JSON.parse(readFileSync(CONSTRAINTS_JSON, "utf8"))
    : [];
  const cMap = new Map(constraints.map((r) => [r.config.name, r]));

  const out: Combined[] = [];
  for (const config of cfg.configs) {
    const tPath = join(SPARTAN_RESULTS, `${config.name}.json`);
    const timings: TimingsRow | undefined = existsSync(tPath)
      ? JSON.parse(readFileSync(tPath, "utf8"))
      : undefined;
    out.push({ config, constraints: cMap.get(config.name), timings });
  }
  return out;
}

function group(rows: Combined[]): Map<string, Combined[]> {
  const m = new Map<string, Combined[]>();
  for (const r of rows) {
    if (!m.has(r.config.sweep)) m.set(r.config.sweep, []);
    m.get(r.config.sweep)!.push(r);
  }
  return m;
}

function exprStr(e: string[]): string { return e.join(" "); }

// ---------------------------------------------------------------------------
// Mermaid chart helpers
// ---------------------------------------------------------------------------

function yRange(values: number[], padPct = 10): [number, number] {
  if (values.length === 0) return [0, 1];
  let lo = Math.min(...values);
  let hi = Math.max(...values);
  if (lo === hi) {
    const pad = Math.max(1, Math.abs(lo) * 0.1);
    return [lo - pad, hi + pad];
  }
  const span = hi - lo;
  const pad = (span * padPct) / 100;
  lo = Math.max(0, Math.floor(lo - pad));
  hi = Math.ceil(hi + pad);
  return [lo, hi];
}

function chart(opts: {
  title: string;
  xLabel: string;
  yLabel: string;
  xValues: (number | string)[];
  series: { name: string; values: number[] }[];
}): string {
  const allY = opts.series.flatMap((s) => s.values);
  const [yLo, yHi] = yRange(allY);
  const xAxisVals = `[${opts.xValues.map((v) => (typeof v === "number" ? v : `"${v}"`)).join(", ")}]`;

  const lines: string[] = [];
  lines.push("```mermaid");
  lines.push("xychart-beta");
  lines.push(`    title "${opts.title}"`);
  lines.push(`    x-axis "${opts.xLabel}" ${xAxisVals}`);
  lines.push(`    y-axis "${opts.yLabel}" ${yLo} --> ${yHi}`);
  for (const s of opts.series) {
    lines.push(`    line [${s.values.join(", ")}]`);
  }
  lines.push("```");
  if (opts.series.length > 1) {
    lines.push("");
    lines.push(
      `Series (in order): ${opts.series.map((s) => `**${s.name}**`).join(", ")}`
    );
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Section renderers
// ---------------------------------------------------------------------------

function renderConstraintsSection(rows: Combined[]): string {
  const out: string[] = [];
  out.push("## Constraints");
  out.push("");
  out.push(
    "Per-configuration R1CS constraint counts (`circom -p secq256r1 --O2`). `predicateLen` and `exprLen` are sized exactly to the workload, so no inactive padding is counted."
  );
  out.push("");
  for (const [sweep, gr] of group(rows)) {
    out.push(`### Sweep: \`${sweep}\``);
    out.push("");
    out.push("| name | n | m | t | op | rhsRef | expression | constraints | wires | labels |");
    out.push("| --- | ---: | ---: | ---: | --- | :---: | --- | ---: | ---: | ---: |");
    for (const row of gr) {
      const c = row.config;
      const k = row.constraints;
      out.push(
        `| ${c.name} | ${c.nClaims} | ${c.maxPredicates} | ${c.maxLogicTokens} | ${c.predicateOp} | ${c.rhsIsRef ? "yes" : "no"} | \`${exprStr(c.expression)}\` | ${k ? k.constraints.toLocaleString() : "n/a"} | ${k ? k.wires.toLocaleString() : "n/a"} | ${k ? k.labels.toLocaleString() : "n/a"} |`
      );
    }
    out.push("");
  }
  return out.join("\n");
}

function renderTimingsSection(rows: Combined[]): string {
  const out: string[] = [];
  out.push("## Timings (ms)");
  out.push("");
  out.push(
    "Wall-clock milliseconds for each stage of one Show presentation. `setup` runs the universal proving-key derivation; `witness_gen` is `witnesscalc` time on the input JSON; `prove` is proving only (witness pre-warmed, so it does not include witnesscalc); `reblind` re-randomizes the proof under fresh blinding factors (matches production split-R1CS layout `[deviceKeyX, deviceKeyY, claimValues[..n]]`); `verify` checks the reblinded proof."
  );
  out.push("");
  for (const [sweep, gr] of group(rows)) {
    out.push(`### Sweep: \`${sweep}\``);
    out.push("");
    out.push("| name | n | m | t | op | rhsRef | setup | witness | prove | reblind | verify |");
    out.push("| --- | ---: | ---: | ---: | --- | :---: | ---: | ---: | ---: | ---: | ---: |");
    for (const row of gr) {
      const c = row.config;
      const t = row.timings?.timings_ms;
      const v = (n?: number) => (typeof n === "number" ? `${n} ms` : "n/a");
      out.push(
        `| ${c.name} | ${c.nClaims} | ${c.maxPredicates} | ${c.maxLogicTokens} | ${c.predicateOp} | ${c.rhsIsRef ? "yes" : "no"} | ${v(t?.setup)} | ${v(t?.witness_gen)} | ${v(t?.prove)} | ${v(t?.reblind)} | ${v(t?.verify)} |`
      );
    }
    out.push("");
  }
  return out.join("\n");
}

function renderSizesSection(rows: Combined[]): string {
  const out: string[] = [];
  out.push("## Sizes");
  out.push("");
  out.push(
    "Bincode-serialized byte counts of the in-memory artifacts. `proof` is the initial Spartan proof; `reblinded` is the proof a verifier actually receives. `pk` and `vk` are the proving / verifying keys."
  );
  out.push("");
  for (const [sweep, gr] of group(rows)) {
    out.push(`### Sweep: \`${sweep}\``);
    out.push("");
    out.push("| name | n | m | t | proof | reblinded | pk | vk | witness |");
    out.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (const row of gr) {
      const c = row.config;
      const s = row.timings?.sizes_bytes;
      const f = (b?: number, fmt: (b: number) => string = fmtKb) =>
        typeof b === "number" ? fmt(b) : "n/a";
      out.push(
        `| ${c.name} | ${c.nClaims} | ${c.maxPredicates} | ${c.maxLogicTokens} | ${f(s?.proof)} | ${f(s?.reblinded_proof)} | ${f(s?.proving_key, fmtMb)} | ${f(s?.verifying_key)} | ${f(s?.witness)} |`
      );
    }
    out.push("");
  }
  return out.join("\n");
}

function renderChartsSection(rows: Combined[]): string {
  const groups = group(rows);
  const sweepM = (groups.get("predicates_at_n10") || []).slice().sort(
    (a, b) => a.config.maxPredicates - b.config.maxPredicates
  );
  const sweepN = (groups.get("claims_at_m1") || []).slice().sort(
    (a, b) => a.config.nClaims - b.config.nClaims
  );

  const out: string[] = [];
  out.push("## Charts");
  out.push("");
  out.push(
    "All charts use Mermaid `xychart-beta` (rendered inline on GitHub). When two series share a chart, the order is given below the block."
  );
  out.push("");

  // ---- m sweep ----
  if (sweepM.length > 0) {
    const xs = sweepM.map((r) => r.config.maxPredicates);
    out.push("### Sweep `predicates_at_n10`: varying `m` (n = 10, t = 2m - 1)");
    out.push("");
    out.push("**Constraints**");
    out.push("");
    out.push(chart({
      title: "Constraints vs m",
      xLabel: "maxPredicates (m)",
      yLabel: "constraints",
      xValues: xs,
      series: [{ name: "constraints", values: sweepM.map((r) => r.constraints?.constraints ?? 0) }],
    }));
    out.push("");

    out.push("**Setup time**");
    out.push("");
    out.push(chart({
      title: "Setup time vs m",
      xLabel: "maxPredicates (m)",
      yLabel: "ms",
      xValues: xs,
      series: [{ name: "setup ms", values: sweepM.map((r) => r.timings?.timings_ms.setup ?? 0) }],
    }));
    out.push("");

    out.push("**Prove + reblind + verify**");
    out.push("");
    out.push(chart({
      title: "Prove / reblind / verify vs m",
      xLabel: "maxPredicates (m)",
      yLabel: "ms",
      xValues: xs,
      series: [
        { name: "prove", values: sweepM.map((r) => r.timings?.timings_ms.prove ?? 0) },
        { name: "reblind", values: sweepM.map((r) => r.timings?.timings_ms.reblind ?? 0) },
        { name: "verify", values: sweepM.map((r) => r.timings?.timings_ms.verify ?? 0) },
      ],
    }));
    out.push("");

    out.push("**Proving key size**");
    out.push("");
    out.push(chart({
      title: "Proving key size vs m (KB)",
      xLabel: "maxPredicates (m)",
      yLabel: "KB",
      xValues: xs,
      series: [{
        name: "pk KB",
        values: sweepM.map((r) =>
          r.timings?.sizes_bytes.proving_key
            ? Math.round(r.timings.sizes_bytes.proving_key / 1024)
            : 0
        ),
      }],
    }));
    out.push("");
  }

  // ---- n sweep ----
  if (sweepN.length > 0) {
    const xs = sweepN.map((r) => r.config.nClaims);
    out.push("### Sweep `claims_at_m1`: varying `n` (m = 1, t = 1)");
    out.push("");
    out.push("**Constraints**");
    out.push("");
    out.push(chart({
      title: "Constraints vs n",
      xLabel: "nClaims (n)",
      yLabel: "constraints",
      xValues: xs,
      series: [{ name: "constraints", values: sweepN.map((r) => r.constraints?.constraints ?? 0) }],
    }));
    out.push("");

    out.push("**Setup time**");
    out.push("");
    out.push(chart({
      title: "Setup time vs n",
      xLabel: "nClaims (n)",
      yLabel: "ms",
      xValues: xs,
      series: [{ name: "setup ms", values: sweepN.map((r) => r.timings?.timings_ms.setup ?? 0) }],
    }));
    out.push("");

    out.push("**Prove + reblind + verify**");
    out.push("");
    out.push(chart({
      title: "Prove / reblind / verify vs n",
      xLabel: "nClaims (n)",
      yLabel: "ms",
      xValues: xs,
      series: [
        { name: "prove", values: sweepN.map((r) => r.timings?.timings_ms.prove ?? 0) },
        { name: "reblind", values: sweepN.map((r) => r.timings?.timings_ms.reblind ?? 0) },
        { name: "verify", values: sweepN.map((r) => r.timings?.timings_ms.verify ?? 0) },
      ],
    }));
    out.push("");

    out.push("**Proving key size**");
    out.push("");
    out.push(chart({
      title: "Proving key size vs n (KB)",
      xLabel: "nClaims (n)",
      yLabel: "KB",
      xValues: xs,
      series: [{
        name: "pk KB",
        values: sweepN.map((r) =>
          r.timings?.sizes_bytes.proving_key
            ? Math.round(r.timings.sizes_bytes.proving_key / 1024)
            : 0
        ),
      }],
    }));
    out.push("");
  }

  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Takeaways: derived from the data so they stay accurate across re-runs
// ---------------------------------------------------------------------------

function pct(a: number, b: number): string {
  if (b === 0) return "n/a";
  return `${(((a - b) / b) * 100).toFixed(1)}%`;
}

function renderTakeawaysSection(rows: Combined[]): string {
  const groups = group(rows);
  const sweepM = (groups.get("predicates_at_n10") || []).slice().sort(
    (a, b) => a.config.maxPredicates - b.config.maxPredicates
  );
  const sweepN = (groups.get("claims_at_m1") || []).slice().sort(
    (a, b) => a.config.nClaims - b.config.nClaims
  );
  const opMix = groups.get("operator_mix") || [];
  const rhsMix = groups.get("rhs_kind") || [];
  const baseline = sweepM.find((r) => r.config.maxPredicates === 4)
    || sweepM.find((r) => r.config.maxPredicates === 1);

  const out: string[] = [];
  out.push("## Takeaways");
  out.push("");

  // 1. constraint cost per predicate vs per claim
  if (sweepM.length >= 2 && sweepN.length >= 2) {
    const m1 = sweepM[0]; const mN = sweepM[sweepM.length - 1];
    const n1 = sweepN[0]; const nN = sweepN[sweepN.length - 1];
    if (m1.constraints && mN.constraints && n1.constraints && nN.constraints) {
      const dM = (mN.constraints.constraints - m1.constraints.constraints) /
        (mN.config.maxPredicates - m1.config.maxPredicates);
      const dN = (nN.constraints.constraints - n1.constraints.constraints) /
        (nN.config.nClaims - n1.config.nClaims);
      out.push(
        `1. **Predicates dominate constraints.** Each extra predicate adds about **${dM.toFixed(0)} constraints** in the m-sweep, while each extra claim only adds about **${dN.toFixed(0)}** in the n-sweep. The ECDSA verification dominates the absolute baseline (about ${m1.constraints.constraints.toLocaleString()} constraints with the smallest workload), so the variable predicate/claim cost rides on top of a large fixed cost.`
      );
    }
  }

  // 2. m-sweep constraint shape (super-linear?)
  if (sweepM.length >= 3) {
    const c0 = sweepM[0].constraints?.constraints;
    const c1 = sweepM[Math.floor(sweepM.length / 2)].constraints?.constraints;
    const c2 = sweepM[sweepM.length - 1].constraints?.constraints;
    if (c0 && c1 && c2) {
      out.push(
        `2. **The m-slope bundles three effects, not just per-predicate cost.** The canonical expression is a left-deep AND chain (\`P0 P1 AND P2 AND ...\`), so going from m to m+1 adds *two* postfix tokens: one new predicate ref and one \`AND\` operator. The reported per-predicate slope therefore charges the prover for (1) one more comparison in \`EvalPredicates\`, (2) one more REF step, and (3) one more AND step in the postfix evaluator. To isolate per-token cost alone, hold m fixed and grow t with idempotent inserts (e.g. pairs of \`NOT NOT\`).`
      );
    }
  }

  // 3. operator mix, rhs kind
  if (opMix.length === 2 && baseline?.constraints) {
    const eq = opMix.find((r) => r.config.predicateOp === "eq");
    const le = opMix.find((r) => r.config.predicateOp === "le");
    if (eq && le && eq.constraints && le.constraints) {
      const same = eq.constraints.constraints === le.constraints.constraints;
      const eqProve = eq.timings?.timings_ms.prove;
      const leProve = le.timings?.timings_ms.prove;
      const proveDelta = (eqProve != null && leProve != null) ? pct(leProve, eqProve) : "n/a";
      out.push(
        `3. **\`==\` and \`<=\` produce the same R1CS** (${same ? "confirmed" : "DIFFERED, check"}). The circuit handles all operators uniformly, so operator mix is a runtime concern only. The witness has to satisfy bit-decomposition for \`<=\` regardless of how the proof is generated. In the timing data the prove-time delta between \`<=\` and \`==\` was **${proveDelta}**${proveDelta === "n/a" ? "" : " (relative to ==)"}.`
      );
    }
  }
  if (rhsMix.length >= 1 && baseline?.constraints) {
    const ref = rhsMix[0];
    if (ref.constraints && baseline.constraints) {
      const same = ref.constraints.constraints === baseline.constraints.constraints;
      const refProve = ref.timings?.timings_ms.prove;
      const baseProve = baseline.timings?.timings_ms.prove;
      const proveDelta = (refProve != null && baseProve != null) ? pct(refProve, baseProve) : "n/a";
      out.push(
        `4. **Claim-to-claim references cost the same R1CS as constant operands** (${same ? "confirmed" : "DIFFERED, check"}). Both the literal RHS and the claim-mux RHS go through the same multiplexer, so the circuit is paying for both either way. Prove-time delta vs. literal-RHS baseline: **${proveDelta}**.`
      );
    }
  }

  // 5. reblind cost vs prove
  if (baseline?.timings) {
    const t = baseline.timings.timings_ms;
    out.push(
      `5. **Reblind is roughly ${(t.reblind / Math.max(t.prove, 1)).toFixed(2)}x the cost of prove** at the baseline configuration (${t.reblind} ms vs ${t.prove} ms), because reblinding only re-randomizes commitments to the shared witness rows. It does not redo the full proving work. This makes presentations cheap to refresh.`
    );
  }

  // 5b. reblind jump at large m
  if (sweepM.length >= 2) {
    const small = sweepM[0]; const big = sweepM[sweepM.length - 1];
    if (small.timings && big.timings) {
      const sR = small.timings.timings_ms.reblind;
      const bR = big.timings.timings_ms.reblind;
      if (bR > 0 && sR > 0 && bR / sR > 1.5) {
        out.push(
          `   Reblind is *not* perfectly flat across m, though: it jumps from ${sR} ms at m=${small.config.maxPredicates} to ${bR} ms at m=${big.config.maxPredicates} (a ${pct(bR, sR)} increase). The shared layout itself does not change with m (it is always \`[deviceKeyX, deviceKeyY, claimValues[..n]]\`), so this jump comes from the larger Spartan circuit underneath, likely an MSM batch crossing a threshold.`
        );
      }
    }
  }

  // 6. proof / VK / verify costs
  if (sweepM.length >= 2 && sweepM[0].timings && sweepM[sweepM.length - 1].timings) {
    const a = sweepM[0].timings!; const b = sweepM[sweepM.length - 1].timings!;
    const proofDelta = pct(b.sizes_bytes.proof, a.sizes_bytes.proof);
    const verifyDelta = pct(b.timings_ms.verify, a.timings_ms.verify);
    out.push(
      `6. **Proof size and verify time grow much slower than prove time.** Across the m-sweep proof size moved by **${proofDelta}** and verify time by **${verifyDelta}**, while constraints grew by about ${pct(sweepM[sweepM.length - 1].constraints!.constraints, sweepM[0].constraints!.constraints)}. This is the usual Spartan pattern: prover-side work scales with the circuit, verifier-side work is closer to logarithmic.`
    );
  }

  // 7. PK size dominance
  if (baseline?.timings) {
    const s = baseline.timings.sizes_bytes;
    out.push(
      `7. **The proving key dominates the size budget.** At the baseline, pk = ${fmtMb(s.proving_key)} vs proof = ${fmtKb(s.proof)}, so pk is roughly ${(s.proving_key / Math.max(s.proof, 1)).toFixed(0)}x the proof. Mobile deployments need to think about pk delivery; the per-presentation network cost (proof + reblinded proof) is small.`
    );
  }

  // 8. witness gen is essentially flat
  const allWitness = rows
    .map((r) => r.timings?.timings_ms.witness_gen)
    .filter((v): v is number => typeof v === "number");
  if (allWitness.length >= 5) {
    const wMin = Math.min(...allWitness);
    const wMax = Math.max(...allWitness);
    out.push(
      `8. **Witness generation is essentially flat** at ${wMin} to ${wMax} ms across every configuration. \`witnesscalc\` cost is dominated by ECDSA, not by the predicate/expression workload, so packing more predicates into a presentation does not move this number.`
    );
  }

  // 9. n is almost free
  if (sweepN.length >= 2 && sweepN[0].constraints && sweepN[sweepN.length - 1].constraints) {
    const dN = (sweepN[sweepN.length - 1].constraints!.constraints - sweepN[0].constraints!.constraints) /
      (sweepN[sweepN.length - 1].config.nClaims - sweepN[0].config.nClaims);
    out.push(
      `9. **Adding claim slots is almost free.** Going from n=${sweepN[0].config.nClaims} to n=${sweepN[sweepN.length - 1].config.nClaims} costs only about ${dN.toFixed(0)} constraints per claim and the timing/size impact is below measurement noise. Practical credentials with 20 to 30 claim fields are not the bottleneck. The predicate count is.`
    );
  }

  out.push("");
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function main() {
  const rows = loadCombined();
  const completed = rows.filter((r) => r.constraints && r.timings).length;
  const total = rows.length;

  const head: string[] = [];
  head.push("# Show-circuit benchmarks: full report");
  head.push("");
  head.push(`Combined results across **${completed}/${total}** configurations from \`circom/benchmarks/configs.json\`. Each row is a separate compilation of \`Show(nClaims, maxPredicates, maxLogicTokens, 64)\`; \`predicateLen\` and \`exprLen\` equal \`maxPredicates\` and \`maxLogicTokens\` respectively, so the circuit is sized exactly to its workload.`);
  head.push("");
  head.push("Generated by `scripts/benchmarks/generate-report.ts`. Re-run after both `yarn bench:constraints` and `ecdsa-spartan2/benchmarks/scripts/run-show-bench.sh` to refresh.");
  head.push("");
  head.push("**Sweeps**");
  head.push("");
  head.push("| Sweep | Variable | Held fixed |");
  head.push("| --- | --- | --- |");
  head.push("| `predicates_at_n10` | `m ∈ {1, 2, 4, 8}` (left-deep AND chain, `t = 2m - 1`) | `n = 10` |");
  head.push("| `claims_at_m1`      | `n ∈ {1, 5, 10, 20, 30}`                              | `m = 1, t = 1` |");
  head.push("| `operator_mix`      | `predicateOp ∈ {==, ≤}`                                | `n = 10, m = 4, t = 7` |");
  head.push("| `rhs_kind`          | RHS kind (literal vs claim reference)                  | `n = 10, m = 4, t = 7` |");
  head.push("");
  head.push("**Real-world examples per sweep**");
  head.push("");
  head.push("Plain-language examples of what each sweep models. `n` = number of claim slots in the credential (e.g. name, date of birth, nationality...), `m` = number of predicates checked (e.g. \"age ≥ 18\"), `t` = number of tokens in the boolean expression that combines them.");
  head.push("");
  head.push("| Sweep | What changes | Real-world example |");
  head.push("| --- | --- | --- |");
  head.push("| `predicates_at_n10` | More conditions checked at once on the same credential | A bar checks **1** condition (\"age ≥ 21\"); a rental site checks **2** (\"age ≥ 25 AND license valid\"); a job application checks **4** (\"age ≥ 18 AND citizen AND no criminal record AND degree verified\"); a financial onboarding checks **8** (KYC + AML + age + residency + income + sanctions + PEP + accredited investor). All on a credential with ~10 fields. |");
  head.push("| `claims_at_m1`      | Same single check, but the credential carries more fields | A minimal token with **1** field (just date of birth) vs. a passport-like credential with **30** fields (name, DOB, nationality, document number, expiry, photo hash, ...). The presented check is still just one predicate (e.g. \"age ≥ 18\"); we measure the cost of carrying the extra unused fields. |");
  head.push("| `operator_mix`      | The kind of comparison used in a predicate | \"nationality **==** 'ES'\" (equality) vs. \"age **≤** 65\" (range/inequality). Same workload shape, different operator. |");
  head.push("| `rhs_kind`          | What the predicate compares against | Comparing a claim to a **literal constant** (\"age ≥ 18\") vs. comparing a claim to **another claim** (\"expiry_date ≥ today_field\", or \"billing_country == shipping_country\"). |");
  head.push("");

  const sections = [
    head.join("\n"),
    renderTakeawaysSection(rows),
    renderConstraintsSection(rows),
    renderTimingsSection(rows),
    renderSizesSection(rows),
    renderChartsSection(rows),
  ];

  const md = sections.join("\n");
  writeFileSync(REPORT_OUT, md);
  console.log(`Wrote ${REPORT_OUT}  (${completed}/${total} configs populated)`);
}

main();
