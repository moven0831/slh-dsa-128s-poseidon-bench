import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { ProofError } from "./errors.js";
import type { JwtCircuitInputs, ShowCircuitInputs } from "./types.js";

// Circom witness calculators accept any object with string keys
type CircuitInput = Record<string, unknown>;

interface WitnessCalculatorInstance {
  calculateWitness(input: CircuitInput, sanityCheck?: boolean): Promise<bigint[]>;
  calculateBinWitness(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
  calculateWTNSBin(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
}

type WitnessCalculatorBuilder = (
  code: ArrayBuffer | Uint8Array,
  options?: { sanityCheck?: boolean }
) => Promise<WitnessCalculatorInstance>;

export class WitnessCalculator {
  private jwtCalculator: WitnessCalculatorInstance | null = null;
  private showCalculator: WitnessCalculatorInstance | null = null;
  private builder: WitnessCalculatorBuilder | null = null;

  private jwtWasmPath: string;
  private showWasmPath: string;

  constructor(assetsDir?: string) {
    const defaultAssetsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");
    const dir = assetsDir ?? defaultAssetsDir;
    this.jwtWasmPath = join(dir, "jwt.wasm");
    this.showWasmPath = join(dir, "show.wasm");
  }

  async init(): Promise<void> {
    const builderPath = join(dirname(fileURLToPath(import.meta.url)), "..", "assets", "witness_calculator.cjs");
    const module = await import(/* webpackIgnore: true */ builderPath);
    this.builder = module.default ?? module;
  }

  private async loadCalculator(wasmPath: string): Promise<WitnessCalculatorInstance> {
    if (!this.builder) {
      throw new ProofError("WITNESS_GENERATION_FAILED", "Witness calculator not initialized. Call init() first.");
    }
    const wasmBuffer = await readFile(wasmPath);
    return await this.builder(wasmBuffer, { sanityCheck: true });
  }

  async calculateJwtWitness(inputs: JwtCircuitInputs | CircuitInput): Promise<bigint[]> {
    if (!this.jwtCalculator) {
      this.jwtCalculator = await this.loadCalculator(this.jwtWasmPath);
    }
    return await this.jwtCalculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateShowWitness(inputs: ShowCircuitInputs | CircuitInput): Promise<bigint[]> {
    if (!this.showCalculator) {
      this.showCalculator = await this.loadCalculator(this.showWasmPath);
    }
    return await this.showCalculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateJwtWitnessWtns(inputs: JwtCircuitInputs | CircuitInput): Promise<Uint8Array> {
    if (!this.jwtCalculator) {
      this.jwtCalculator = await this.loadCalculator(this.jwtWasmPath);
    }
    return await this.jwtCalculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateShowWitnessWtns(inputs: ShowCircuitInputs | CircuitInput): Promise<Uint8Array> {
    if (!this.showCalculator) {
      this.showCalculator = await this.loadCalculator(this.showWasmPath);
    }
    return await this.showCalculator.calculateWTNSBin(inputs as CircuitInput, true);
  }
}
