/// <reference types="node" />
/**
 * Generate a Show-circuit input JSON for one entry in `circom/benchmarks/configs.json`.
 *
 * Sizing (`predicateLen` and `exprLen`) matches `maxPredicates` and `maxLogicTokens`,
 * so the witness fully exercises the active region of every input array.
 *
 * Run from the `circom/` directory:
 *   npx ts-node scripts/benchmarks/generate-show-input.ts <config-name> <output-path>
 */

import * as nodeCrypto from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join, resolve } from "path";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";
import { bufferToBigInt } from "../../src/utils";

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

const OP_CODE: Record<BenchConfig["predicateOp"], number> = { le: 0, ge: 1, eq: 2 };

function tokenize(expr: string[], maxPredicates: number): { types: number[]; values: number[] } {
  const types: number[] = [];
  const values: number[] = [];
  for (const tok of expr) {
    if (tok === "AND") { types.push(1); values.push(0); continue; }
    if (tok === "OR")  { types.push(2); values.push(0); continue; }
    if (tok === "NOT") { types.push(3); values.push(0); continue; }
    if (tok.startsWith("P")) {
      const idx = Number(tok.slice(1));
      if (Number.isNaN(idx) || idx < 0 || idx >= maxPredicates) {
        throw new Error(`Predicate ref ${tok} out of range [0, ${maxPredicates})`);
      }
      types.push(0);
      values.push(idx);
      continue;
    }
    throw new Error(`Unknown token "${tok}", expected P<i>, AND, OR, NOT`);
  }
  return { types, values };
}

function makeClaimValues(nClaims: number): bigint[] {
  // Use distinct values so claim-to-claim comparisons aren't trivially equal.
  // Cap below 2^valueBits; valueBits = 64 in configs.json.
  const out: bigint[] = [];
  for (let i = 0; i < nClaims; i++) {
    out.push(1_000_000n + BigInt(i));
  }
  return out;
}

function pickRhs(config: BenchConfig, claimValues: bigint[], predicateIndex: number): {
  rhsIsRef: bigint;
  rhsValue: bigint;
} {
  if (config.rhsIsRef) {
    // Reference another claim. Force the comparison to be satisfied:
    //   le: claim[i] <= claim[i+1]   (claim values are increasing)
    //   ge: claim[i+1] >= claim[i]
    //   eq: claim[i] == claim[i] (use itself)
    const i = predicateIndex % config.nClaims;
    let refIndex = i;
    if (config.predicateOp === "le") refIndex = Math.min(i + 1, config.nClaims - 1);
    if (config.predicateOp === "ge") refIndex = Math.max(i - 1, 0);
    return { rhsIsRef: 1n, rhsValue: BigInt(refIndex) };
  }
  // Literal RHS: pick a value that satisfies the predicate against the claim.
  const i = predicateIndex % config.nClaims;
  const v = claimValues[i];
  if (config.predicateOp === "le") return { rhsIsRef: 0n, rhsValue: v + 1n };
  if (config.predicateOp === "ge") return { rhsIsRef: 0n, rhsValue: v - 1n };
  return { rhsIsRef: 0n, rhsValue: v };
}

function buildShowInput(config: BenchConfig) {
  const { nClaims, maxPredicates, maxLogicTokens } = config;
  if (nClaims < 1) throw new Error("nClaims must be >= 1");
  if (maxPredicates < 1) throw new Error("maxPredicates must be >= 1");
  if (maxLogicTokens < 1) throw new Error("maxLogicTokens must be >= 1");

  // Device key + ECDSA signature on a fresh nonce (the Show circuit verifies it).
  const devicePrivateKey = p256.utils.randomPrivateKey();
  const point = p256.ProjectivePoint.fromPrivateKey(devicePrivateKey);
  const deviceKeyX = point.x;
  const deviceKeyY = point.y;

  const nonce = nodeCrypto.randomBytes(24);
  const messageHash = sha256(nonce);
  const sig = p256.sign(messageHash, devicePrivateKey);

  const Fq = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
  const sigSinverse = Fq.inv(sig.s);
  const messageHashBigInt = bufferToBigInt(Buffer.from(messageHash));
  const messageHashModQ = messageHashBigInt % Fq.ORDER;

  const claimValues = makeClaimValues(nClaims);

  const predicateClaimRefs: bigint[] = [];
  const predicateOps: bigint[] = [];
  const predicateRhsIsRef: bigint[] = [];
  const predicateRhsValues: bigint[] = [];
  for (let p = 0; p < maxPredicates; p++) {
    const { rhsIsRef, rhsValue } = pickRhs(config, claimValues, p);
    predicateClaimRefs.push(BigInt(p % nClaims));
    predicateOps.push(BigInt(OP_CODE[config.predicateOp]));
    predicateRhsIsRef.push(rhsIsRef);
    predicateRhsValues.push(rhsValue);
  }

  const { types, values } = tokenize(config.expression, maxPredicates);
  if (types.length !== maxLogicTokens) {
    throw new Error(
      `Tokenized expression length (${types.length}) does not equal maxLogicTokens (${maxLogicTokens}); configs.json should match`
    );
  }

  return {
    deviceKeyX: deviceKeyX.toString(),
    deviceKeyY: deviceKeyY.toString(),
    sig_r: sig.r.toString(),
    sig_s_inverse: sigSinverse.toString(),
    messageHash: messageHashModQ.toString(),
    predicateLen: maxPredicates.toString(),
    claimValues: claimValues.map((v) => v.toString()),
    predicateClaimRefs: predicateClaimRefs.map((v) => v.toString()),
    predicateOps: predicateOps.map((v) => v.toString()),
    predicateRhsIsRef: predicateRhsIsRef.map((v) => v.toString()),
    predicateRhsValues: predicateRhsValues.map((v) => v.toString()),
    tokenTypes: types.map((v) => v.toString()),
    tokenValues: values.map((v) => v.toString()),
    exprLen: maxLogicTokens.toString(),
  };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error("Usage: ts-node generate-show-input.ts <config-name> <output-path>");
    process.exit(1);
  }
  const [configName, outputPath] = args;

  const configsPath = resolve(__dirname, "..", "..", "benchmarks", "configs.json");
  const file: ConfigsFile = JSON.parse(readFileSync(configsPath, "utf8"));
  const config = file.configs.find((c) => c.name === configName);
  if (!config) {
    console.error(`Config "${configName}" not found in ${configsPath}`);
    process.exit(1);
  }

  const input = buildShowInput(config);
  const outDir = dirname(outputPath);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSync(outputPath, JSON.stringify(input, null, 2));
  console.log(`Wrote ${outputPath}`);
}

main();
