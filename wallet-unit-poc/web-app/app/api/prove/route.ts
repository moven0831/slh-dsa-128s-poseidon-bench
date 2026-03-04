import { NextResponse } from "next/server";
import { getBackend, getWitnessCalculator } from "@/lib/sdk-server";
import { deserializeBigInts } from "@/lib/serialize";
import type { JwtCircuitInputs, ShowCircuitInputs } from "openac-sdk";

export const maxDuration = 120; // seconds (for Vercel; locally unlimited)

interface StepTiming {
  name: string;
  durationMs: number;
}

async function timed<T>(name: string, fn: () => Promise<T>): Promise<{ result: T; step: StepTiming }> {
  const start = performance.now();
  const result = await fn();
  const durationMs = Math.round(performance.now() - start);
  return { result, step: { name, durationMs } };
}

export async function POST(request: Request) {
  try {
    const { jwtInputs: rawJwt, showInputs: rawShow } = await request.json();

    const jwtInputs = deserializeBigInts(rawJwt) as JwtCircuitInputs;
    const showInputs = deserializeBigInts(rawShow) as ShowCircuitInputs;

    const backend = getBackend();
    const witnessCalc = await getWitnessCalculator();
    const steps: StepTiming[] = [];
    const totalStart = performance.now();

    // 1. JWT witness generation
    const { result: jwtWitness, step: s1 } = await timed(
      "JWT Witness Generation",
      () => witnessCalc.calculateJwtWitness(jwtInputs),
    );
    steps.push(s1);

    // 2. Show witness generation
    const { result: showWitness, step: s2 } = await timed(
      "Show Witness Generation",
      () => witnessCalc.calculateShowWitness(showInputs),
    );
    steps.push(s2);

    // 3. Generate shared blinds
    const { step: s3 } = await timed(
      "Generate Shared Blinds",
      () => backend.generateSharedBlinds(),
    );
    steps.push(s3);

    // 4. Prove Prepare
    const { step: s4 } = await timed(
      "Prove Prepare",
      () => backend.provePrepare(),
    );
    steps.push(s4);

    // 5. Reblind Prepare
    const { step: s5 } = await timed(
      "Reblind Prepare",
      () => backend.reblindPrepare(),
    );
    steps.push(s5);

    // 6. Prove Show
    const { step: s6 } = await timed(
      "Prove Show",
      () => backend.proveShow(),
    );
    steps.push(s6);

    // 7. Reblind Show
    const { step: s7 } = await timed(
      "Reblind Show",
      () => backend.reblindShow(),
    );
    steps.push(s7);

    const totalMs = Math.round(performance.now() - totalStart);

    // Extract witness results
    const ageAbove18 = showWitness[1] === 1n;
    const deviceKeyX = jwtWitness[97]?.toString() ?? "";
    const deviceKeyY = jwtWitness[98]?.toString() ?? "";

    return NextResponse.json({
      success: true,
      steps,
      totalMs,
      witnessResults: { ageAbove18, deviceKeyX, deviceKeyY },
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 500 },
    );
  }
}
