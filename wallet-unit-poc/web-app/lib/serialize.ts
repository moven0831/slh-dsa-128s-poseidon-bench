// BigInt <-> string JSON helpers for transporting circuit inputs between
// browser and API routes. BigInt is not natively JSON-serializable.

interface BigIntWrapper {
  __bigint: string;
}

function isBigIntWrapper(v: unknown): v is BigIntWrapper {
  return (
    typeof v === "object" &&
    v !== null &&
    "__bigint" in v &&
    typeof (v as BigIntWrapper).__bigint === "string"
  );
}

/** Replace BigInt values with { __bigint: "123" } wrappers for JSON.stringify. */
export function serializeBigInts(obj: unknown): unknown {
  if (typeof obj === "bigint") {
    return { __bigint: obj.toString() };
  }
  if (Array.isArray(obj)) {
    return obj.map(serializeBigInts);
  }
  if (typeof obj === "object" && obj !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = serializeBigInts(value);
    }
    return result;
  }
  return obj;
}

/** Restore BigInt values from { __bigint: "123" } wrappers after JSON.parse. */
export function deserializeBigInts(obj: unknown): unknown {
  if (isBigIntWrapper(obj)) {
    return BigInt(obj.__bigint);
  }
  if (Array.isArray(obj)) {
    return obj.map(deserializeBigInts);
  }
  if (typeof obj === "object" && obj !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = deserializeBigInts(value);
    }
    return result;
  }
  return obj;
}
