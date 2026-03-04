import { NextResponse } from "next/server";
import { Credential } from "openac-sdk";

export async function POST(request: Request) {
  try {
    const { jwt, disclosures } = await request.json();

    const credential = Credential.parse(jwt, disclosures);
    const birthdayIdx = credential.findBirthdayClaim();
    const deviceKey = credential.deviceBindingKey;

    return NextResponse.json({
      success: true,
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
