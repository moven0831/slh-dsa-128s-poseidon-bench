import { NextResponse } from "next/server";
import { Credential } from "openac-sdk";
import { generateTestJwt } from "@/lib/test-data";

export async function POST(request: Request) {
  try {
    const body = await request.json();

    let jwt: string;
    let disclosures: string[];
    let issuerPublicKey: unknown;
    let devicePrivateKeyHex: string;

    if (body.generateTest) {
      // Generate a self-contained test JWT
      const testData = generateTestJwt();
      jwt = testData.jwt;
      disclosures = testData.disclosures;
      issuerPublicKey = testData.issuerPublicKey;
      devicePrivateKeyHex = testData.devicePrivateKeyHex;
    } else {
      jwt = body.jwt;
      disclosures = body.disclosures;
      issuerPublicKey = body.issuerPublicKey;
      devicePrivateKeyHex = body.devicePrivateKeyHex;
    }

    const credential = Credential.parse(jwt, disclosures);
    const birthdayIdx = credential.findBirthdayClaim();
    const deviceKey = credential.deviceBindingKey;

    return NextResponse.json({
      success: true,
      jwt,
      disclosures,
      issuerPublicKey,
      devicePrivateKeyHex,
      claims: credential.claims,
      birthdayIdx,
      deviceKey,
      disclosureHashes: credential.disclosureHashes,
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 400 },
    );
  }
}
