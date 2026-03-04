import { NextResponse } from "next/server";
import {
  Credential,
  buildJwtCircuitInputs,
  buildShowCircuitInputs,
  signDeviceNonce,
  DEFAULT_JWT_PARAMS,
  DEFAULT_SHOW_PARAMS,
} from "openac-sdk";
import { serializeBigInts } from "@/lib/serialize";

export async function POST(request: Request) {
  try {
    const {
      jwt,
      disclosures,
      issuerPublicKey,
      devicePrivateKeyHex,
      verifierNonce,
    } = await request.json();

    // Parse credential
    const credential = Credential.parse(jwt, disclosures);
    const birthdayIdx = credential.findBirthdayClaim();
    if (birthdayIdx === null) {
      return NextResponse.json(
        { success: false, error: "No birthday claim found in credential" },
        { status: 400 },
      );
    }

    // Build decode flags: 1 for roc_birthday, 0 for others
    const decodeFlags = credential.claims.map((c) =>
      c.name === "roc_birthday" ? 1 : 0,
    );
    const additionalMatches = credential.disclosureHashes;

    // Build JWT (Prepare) circuit inputs
    const jwtInputs = buildJwtCircuitInputs(
      credential,
      issuerPublicKey,
      DEFAULT_JWT_PARAMS,
      additionalMatches,
      decodeFlags,
      birthdayIdx,
    );

    // Sign device nonce for Show circuit
    const deviceSignature = signDeviceNonce(verifierNonce, devicePrivateKeyHex);
    const deviceKey = credential.deviceBindingKey!;
    const birthdayClaim = disclosures[birthdayIdx];

    const now = new Date();
    const currentDate = {
      year: now.getFullYear(),
      month: now.getMonth() + 1,
      day: now.getDate(),
    };

    // Build Show circuit inputs
    const showInputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      verifierNonce,
      deviceSignature,
      deviceKey,
      birthdayClaim,
      currentDate,
    );

    return NextResponse.json({
      success: true,
      jwtInputs: serializeBigInts(jwtInputs),
      showInputs: serializeBigInts(showInputs),
      birthdayIdx,
      currentDate,
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 400 },
    );
  }
}
