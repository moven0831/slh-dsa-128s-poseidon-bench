import { NextResponse } from "next/server";
import { getBackend } from "@/lib/sdk-server";

export async function POST() {
  try {
    const backend = getBackend();
    const start = performance.now();

    const [prepareResult, showResult] = await Promise.all([
      backend.verifyPrepare(),
      backend.verifyShow(),
    ]);

    const durationMs = Math.round(performance.now() - start);

    return NextResponse.json({
      success: true,
      prepare: {
        valid: prepareResult.valid,
        output: prepareResult.output,
      },
      show: {
        valid: showResult.valid,
        output: showResult.output,
      },
      durationMs,
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 500 },
    );
  }
}
