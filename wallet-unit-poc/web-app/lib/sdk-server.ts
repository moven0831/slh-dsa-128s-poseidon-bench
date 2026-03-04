// Singleton instances of NativeBackend and WitnessCalculator for server-side use.
// These are heavy to initialize, so we reuse them across API route calls.

import { NativeBackend, WitnessCalculator } from "openac-sdk";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "..", "openac-sdk", "assets");

let _backend: NativeBackend | null = null;
let _witness: WitnessCalculator | null = null;

export function getBackend(): NativeBackend {
  if (!_backend) {
    _backend = new NativeBackend();
  }
  return _backend;
}

export async function getWitnessCalculator(): Promise<WitnessCalculator> {
  if (!_witness) {
    _witness = new WitnessCalculator(ASSETS_DIR);
    await _witness.init();
  }
  return _witness;
}
