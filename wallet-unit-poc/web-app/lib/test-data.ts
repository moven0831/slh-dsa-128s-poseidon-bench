// Self-contained ES256 SD-JWT generator for the demo.
// Adapted from openac-sdk/tests/e2e.test.ts — uses only @noble/curves.

import { p256 } from "@noble/curves/nist";
import { sha256 } from "@noble/hashes/sha2";

// --- Encoding helpers (pure, no Node.js Buffer dependency) ---

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bigintToBytes(value: bigint, byteLength: number): Uint8Array {
  const hex = value.toString(16).padStart(byteLength * 2, "0");
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBase64url(bytes: Uint8Array): string {
  const B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const triplet = (a << 16) | (b << 8) | c;
    result += B64[(triplet >> 18) & 0x3f];
    result += B64[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? B64[(triplet >> 6) & 0x3f]! : "";
    result += i + 2 < bytes.length ? B64[triplet & 0x3f]! : "";
  }
  return result.replace(/\+/g, "-").replace(/\//g, "_");
}

function jsonToBase64url(obj: unknown): string {
  const json = JSON.stringify(obj);
  return bytesToBase64url(new TextEncoder().encode(json));
}

function signES256(signingInput: string, privateKey: Uint8Array): string {
  const msgHash = sha256(signingInput);
  const sig = p256.sign(msgHash, privateKey);
  return bytesToBase64url(sig.toBytes("compact"));
}

function makeDisclosure(salt: string, key: string, value: string): string {
  const json = JSON.stringify([salt, key, value]);
  return bytesToBase64url(new TextEncoder().encode(json));
}

function disclosureDigest(disclosure: string): string {
  const hash = sha256(new TextEncoder().encode(disclosure));
  return bytesToBase64url(hash);
}

// --- Key derivation ---

function derivePublicKey(privateKeyBytes: Uint8Array) {
  let hex = "";
  for (const b of privateKeyBytes) hex += b.toString(16).padStart(2, "0");
  return p256.ProjectivePoint.BASE.multiply(BigInt("0x" + hex));
}

// --- Fixed test keys ---

const ISSUER_PRIVATE_KEY_HEX =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ISSUER_PRIVATE_KEY = hexToBytes(ISSUER_PRIVATE_KEY_HEX);
const ISSUER_POINT = derivePublicKey(ISSUER_PRIVATE_KEY);

const DEVICE_PRIVATE_KEY_HEX =
  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const DEVICE_PRIVATE_KEY = hexToBytes(DEVICE_PRIVATE_KEY_HEX);
const DEVICE_POINT = derivePublicKey(DEVICE_PRIVATE_KEY);

export const ISSUER_PUBLIC_KEY = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: bytesToBase64url(bigintToBytes(ISSUER_POINT.x, 32)),
  y: bytesToBase64url(bigintToBytes(ISSUER_POINT.y, 32)),
};

export const DEVICE_PUBLIC_KEY = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: bytesToBase64url(bigintToBytes(DEVICE_POINT.x, 32)),
  y: bytesToBase64url(bigintToBytes(DEVICE_POINT.y, 32)),
};

export { DEVICE_PRIVATE_KEY_HEX };

export const VERIFIER_NONCE = "test-nonce-12345";

export interface TestJwtData {
  jwt: string;
  disclosures: string[];
  claims: Array<{ salt: string; key: string; value: string }>;
  issuerPublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePublicKey: { kty: "EC"; crv: "P-256"; x: string; y: string };
  devicePrivateKeyHex: string;
}

export function generateTestJwt(): TestJwtData {
  const claimDefs = [
    { salt: "aGVsbG9fd29ybGRfMTIzNDU2", key: "name", value: "Alice" },
    {
      salt: "Z29vZGJ5ZV93b3JsZF83ODkwMTI",
      key: "roc_birthday",
      value: "0890615",
    },
  ];

  const disclosures = claimDefs.map((c) =>
    makeDisclosure(c.salt, c.key, c.value),
  );
  const hashedClaims = disclosures.map((d) => disclosureDigest(d));

  const header = { alg: "ES256", typ: "vc+sd-jwt" };

  const payload = {
    sub: "did:example:subject",
    iss: "did:example:issuer",
    nbf: 1700000000,
    exp: 1800000000,
    cnf: { jwk: DEVICE_PUBLIC_KEY },
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      credentialSubject: {
        _sd: hashedClaims,
        _sd_alg: "sha-256",
      },
    },
    nonce: "fixed-test-nonce",
  };

  const b64Header = jsonToBase64url(header);
  const b64Payload = jsonToBase64url(payload);
  const signingInput = `${b64Header}.${b64Payload}`;
  const b64Signature = signES256(signingInput, ISSUER_PRIVATE_KEY);
  const jwt = `${signingInput}.${b64Signature}`;

  return {
    jwt,
    disclosures,
    claims: claimDefs,
    issuerPublicKey: ISSUER_PUBLIC_KEY,
    devicePublicKey: DEVICE_PUBLIC_KEY,
    devicePrivateKeyHex: DEVICE_PRIVATE_KEY_HEX,
  };
}
