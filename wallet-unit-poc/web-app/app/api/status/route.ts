import { NextResponse } from "next/server";
import { getBackend } from "@/lib/sdk-server";

export async function GET() {
  try {
    const backend = getBackend();
    return NextResponse.json({
      binaryFound: true,
      keysExist: backend.keysExist,
      proofsExist: backend.proofsExist,
    });
  } catch {
    return NextResponse.json({
      binaryFound: false,
      keysExist: false,
      proofsExist: false,
      error: "Rust binary not found. Build with: cd ecdsa-spartan2 && cargo build --release",
    });
  }
}
