import * as fs from "fs";
import * as path from "path";
import * as nodeCrypto from "crypto";

import { generateMockData } from "./mock-vc-generator";
import { LogicToken, generateShowCircuitParams, generateShowInputs, predicateToken, signDeviceNonce } from "./show";

export const CIRCUIT_SIZES: Record<string, number[]> = {
  "1k": [1280, 960, 4, 50, 128],
  "2k": [2048, 2000, 4, 50, 128],
  "4k": [4096, 4000, 4, 50, 128],
  "8k": [8192, 8000, 4, 50, 128],
};

const DEFAULT_INPUT_PARAMS = [1920, 1900, 4, 50, 128] as const;

const FILL_RATIO = 0.8;

function buildConjunctiveExpression(predicateCount: number): number[] {
  const count = Math.max(1, predicateCount);
  if (count === 1) {
    return [predicateToken(0)];
  }

  const expr: number[] = [predicateToken(0), predicateToken(1), LogicToken.AND];
  for (let index = 2; index < count; index++) {
    expr.push(predicateToken(index), LogicToken.AND);
  }

  return expr;
}

function parseEncodedClaim(encodedClaim: string): { key: string; value: string } | null {
  try {
    const decoded = Buffer.from(encodedClaim, "base64url").toString("utf8");
    const parsed = JSON.parse(decoded);
    if (
      Array.isArray(parsed) &&
      parsed.length >= 3 &&
      typeof parsed[1] === "string" &&
      typeof parsed[2] === "string"
    ) {
      return { key: parsed[1], value: parsed[2] };
    }
    return null;
  } catch {
    return null;
  }
}

function inferClaimFormat(encodedClaim: string): bigint {
  const claim = parseEncodedClaim(encodedClaim);
  if (!claim) {
    return 1n;
  }

  const trimmedValue = claim.value.trim();
  if (trimmedValue === "1" || trimmedValue === "0" || /^(true|false)$/i.test(trimmedValue)) {
    return 0n;
  }

  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmedValue)) {
    return 2n;
  }

  if (claim.key.includes("roc") && /^\d{7}$/.test(trimmedValue)) {
    return 3n;
  }

  if (/^\d+$/.test(trimmedValue)) {
    return 1n;
  }

  return 4n;
}

async function generateInputsForSize(sizeName: string): Promise<void> {
  const params = CIRCUIT_SIZES[sizeName];
  if (!params) {
    throw new Error(`Unknown size '${sizeName}'. Valid sizes: ${Object.keys(CIRCUIT_SIZES).join(", ")}`);
  }

  const [, maxB64PayloadLength] = params;
  const targetPayloadLength = Math.floor(maxB64PayloadLength * FILL_RATIO);

  console.log(`\n[${sizeName}] Generating inputs...`);
  console.log(`  Circuit params : [${params.join(", ")}]`);
  console.log(
    `  Target payload : ${targetPayloadLength} / ${maxB64PayloadLength} chars (${Math.round(FILL_RATIO * 100)}% fill)`,
  );

  const mockData = await generateMockData({
    circuitParams: params,
    targetPayloadLength,
  });

  const actualPayloadLen = mockData.token.split(".")[1].length;
  console.log(
    `  Actual payload : ${actualPayloadLen} chars (${((actualPayloadLen / maxB64PayloadLength) * 100).toFixed(1)}% fill)`,
  );

  const maxClaims = Math.max(1, params[2] - 2);
  const claimFormats = Array.from({ length: maxClaims }, (_, index) =>
    index < mockData.claims.length ? inferClaimFormat(mockData.claims[index]) : 1n,
  );
  mockData.circuitInputs.claimFormats = claimFormats;

  const showParams = generateShowCircuitParams(params);
  const preferredClaimIndex = mockData.claims.findIndex((claim) => parseEncodedClaim(claim)?.key === "roc_birthday");
  const selectedClaimIndex = preferredClaimIndex >= 0 ? preferredClaimIndex : 0;

  if (!mockData.claims[selectedClaimIndex]) {
    throw new Error(`Could not find a claim to build Show inputs from (claims.length=${mockData.claims.length})`);
  }

  const nonce = nodeCrypto.randomBytes(24).toString("base64url");
  const deviceSignature = signDeviceNonce(nonce, mockData.devicePrivateKey);
  const activePredicateCount = Math.min(showParams.maxPredicates, Math.max(1, mockData.claims.length));
  const logicExpr = buildConjunctiveExpression(activePredicateCount);

  const showInputs = generateShowInputs(
    showParams,
    nonce,
    deviceSignature,
    mockData.deviceKey,
    mockData.claims,
    logicExpr,
  );
  showInputs.predicateLen = BigInt(activePredicateCount);
  for (let index = 0; index < activePredicateCount; index++) {
    showInputs.predicateClaimRefs[index] = BigInt(index);
    showInputs.predicateCompareValues[index] = showInputs.claimValues[index] ?? 0n;
  }
  showInputs.predicateClaimRefs[0] = BigInt(selectedClaimIndex);
  showInputs.predicateCompareValues[0] = showInputs.claimValues[selectedClaimIndex] ?? 0n;

  const circomDir = path.resolve(__dirname, "..");
  const jwtDefaultDir = path.join(circomDir, "inputs", "jwt");
  const showDefaultDir = path.join(circomDir, "inputs", "show");
  const jwtOutputDir = path.join(circomDir, "inputs", "jwt", sizeName);
  const showOutputDir = path.join(circomDir, "inputs", "show", sizeName);

  fs.mkdirSync(jwtOutputDir, { recursive: true });
  fs.mkdirSync(showOutputDir, { recursive: true });

  const jwtDefaultPath = path.join(jwtDefaultDir, "default.json");
  const showDefaultPath = path.join(showDefaultDir, "default.json");
  const jwtOutputPath = path.join(jwtOutputDir, "default.json");
  const showOutputPath = path.join(showOutputDir, "default.json");

  const bigintReplacer = (_key: string, value: any) => (typeof value === "bigint" ? value.toString() : value);

  const jwtJson = JSON.stringify(mockData.circuitInputs, bigintReplacer, 2);
  const showJson = JSON.stringify(showInputs, bigintReplacer, 2);

  fs.writeFileSync(jwtOutputPath, jwtJson);
  fs.writeFileSync(showOutputPath, showJson);

  console.log(`  JWT  inputs → ${path.relative(circomDir, jwtOutputPath)}`);
  console.log(`  Show inputs → ${path.relative(circomDir, showOutputPath)}`);

  const defaultParams = [...DEFAULT_INPUT_PARAMS];
  const defaultPayloadTarget = Math.floor(defaultParams[1] * FILL_RATIO);
  const defaultMockData = await generateMockData({
    circuitParams: defaultParams,
    targetPayloadLength: defaultPayloadTarget,
  });
  const defaultClaimFormats = Array.from({ length: Math.max(1, defaultParams[2] - 2) }, (_, index) =>
    index < defaultMockData.claims.length ? inferClaimFormat(defaultMockData.claims[index]) : 1n,
  );
  defaultMockData.circuitInputs.claimFormats = defaultClaimFormats;

  const defaultShowParams = generateShowCircuitParams(defaultParams);
  const defaultPreferredClaimIndex = defaultMockData.claims.findIndex(
    (claim) => parseEncodedClaim(claim)?.key === "roc_birthday",
  );
  const defaultSelectedClaimIndex = defaultPreferredClaimIndex >= 0 ? defaultPreferredClaimIndex : 0;
  const defaultNonce = nodeCrypto.randomBytes(24).toString("base64url");
  const defaultDeviceSignature = signDeviceNonce(defaultNonce, defaultMockData.devicePrivateKey);
  const defaultActivePredicateCount = Math.min(
    defaultShowParams.maxPredicates,
    Math.max(1, defaultMockData.claims.length),
  );
  const defaultLogicExpr = buildConjunctiveExpression(defaultActivePredicateCount);
  const defaultShowInputs = generateShowInputs(
    defaultShowParams,
    defaultNonce,
    defaultDeviceSignature,
    defaultMockData.deviceKey,
    defaultMockData.claims,
    defaultLogicExpr,
  );
  defaultShowInputs.predicateLen = BigInt(defaultActivePredicateCount);
  for (let index = 0; index < defaultActivePredicateCount; index++) {
    defaultShowInputs.predicateClaimRefs[index] = BigInt(index);
    defaultShowInputs.predicateCompareValues[index] = defaultShowInputs.claimValues[index] ?? 0n;
  }
  defaultShowInputs.predicateClaimRefs[0] = BigInt(defaultSelectedClaimIndex);
  defaultShowInputs.predicateCompareValues[0] = defaultShowInputs.claimValues[defaultSelectedClaimIndex] ?? 0n;

  fs.mkdirSync(jwtDefaultDir, { recursive: true });
  fs.mkdirSync(showDefaultDir, { recursive: true });
  fs.writeFileSync(jwtDefaultPath, JSON.stringify(defaultMockData.circuitInputs, bigintReplacer, 2));
  fs.writeFileSync(showDefaultPath, JSON.stringify(defaultShowInputs, bigintReplacer, 2));
  console.log(`  JWT  default → ${path.relative(circomDir, jwtDefaultPath)}`);
  console.log(`  Show default → ${path.relative(circomDir, showDefaultPath)}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(`
Usage: npx ts-node src/generate-inputs.ts [options]

Options:
  --size <size>  Generate inputs for a specific circuit size (1k | 2k | 4k | 8k)
  --all          Generate inputs for all sizes (1k, 2k, 4k, 8k)
  -h, --help     Show this help message

Examples:
  npx ts-node src/generate-inputs.ts --size 2k
  npx ts-node src/generate-inputs.ts --all
`);
    process.exit(0);
  }

  if (args.includes("--all")) {
    for (const sizeName of Object.keys(CIRCUIT_SIZES)) {
      await generateInputsForSize(sizeName);
    }
    console.log("\nAll inputs generated successfully.");
    return;
  }

  const sizeIdx = args.indexOf("--size");
  if (sizeIdx === -1 || !args[sizeIdx + 1]) {
    console.error("Error: --size <size> is required (or use --all).");
    process.exit(1);
  }

  const sizeName = args[sizeIdx + 1];
  await generateInputsForSize(sizeName);
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
