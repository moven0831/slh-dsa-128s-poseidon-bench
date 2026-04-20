# mDL Presentation Protocol Spec

A protocol-level specification for verifying an ISO/IEC 18013-5 mobile
driving licence (mDL / mdoc) credential with device binding and,
optionally, zero-knowledge selective disclosure. It covers what must
be true for a presentation to be accepted, not how a particular circuit
or library implements it.

## Actors

- **Issuer.** DMV or government authority. Signs credentials; their
  keys chain to an IACA (Issuing Authority Certification Authority)
  root.
- **Holder.** The person presenting. Holds the credential on a device
  with a secure element.
- **Verifier.** Bar, airline, website, reader. Wants specific facts
  about the holder.

## Inputs

### From the holder (presentation payload)

- **The credential (MSO).** Signed by the issuer. Contains value
  digests, device public key, doctype, namespace, validity window.
- **Disclosed items.** For each claim being shown: the element
  identifier, value, random salt, and digestID.
- **Device signature.** The holder's device signs a session transcript
  (nonce + verifier info + doctype).

### From the verifier (policy and context)

- **Expected doctype**, e.g. `org.iso.18013.5.1.mDL`.
- **Expected namespace**, e.g. `org.iso.18013.5.1`.
- **Current time**, used for the validity window.
- **Session nonce + transcript context.** Fresh per session; prevents
  replay.
- **Ask.** What the verifier wants: raw claim disclosure or a
  predicate (for example, "age ≥ 21").

## Checks

### Authenticity

1. **Issuer signature is valid** over the MSO.
2. **Credential type matches.** DocType in the MSO equals what the
   verifier asked for.
3. **Namespace matches.** Disclosed claims belong to the expected
   namespace.

### Validity window

4. **Activated:** `validFrom ≤ now`.
5. **Not expired:** `now ≤ validUntil`.
6. *(Optional)* **Not revoked.** Check against the issuer's revocation
   list or status mechanism.

### Selective disclosure integrity

For each disclosed claim:

7. **Identifier is what's claimed.** The disclosed element name is
   the one in the preimage.
8. **Value position is anchored.** The byte range treated as the claim
   value starts just past the `"elementValue"` label inside the
   authenticated preimage. This prevents pointing at arbitrary bytes.
9. **Preimage hash matches.** `hash(preimage)` equals the digest the
   issuer signed for that `digestID` in the right namespace.
10. **Salt is present and random**, so digests cannot be precomputed
    dictionary-style.

### Device binding

11. **Device key belongs to this credential.** The public key in the
    device signature is the one the issuer embedded in the MSO
    (`deviceKeyInfo`).
12. **Device signature is valid** over the session transcript.
13. **Nonce is fresh.** Verifier-generated, not reused. Blocks replay.

### Predicate (only if the verifier asked for one)

14. **Predicate evaluates to true** over the normalized claim values,
    e.g. `birth_date ≤ 20080101` for "age ≥ 18".

## Outputs

Depends on what the verifier asked for.

### Disclosure mode

- Validity: yes / no.
- **`validUntilDate`.** The credential's expiry packed as a
  `YYYYMMDD` integer (e.g. `20271231`). Verifier compares against
  their current date in the same format.
- **`deviceKey0`, `deviceKey1`.** The device public key's
  x-coordinate, split into two field-element limbs. Feeds the Show
  circuit for device authentication.
- **`normalizedClaimValues[]`.** One field element per requested
  claim, normalized per the table below.
- Device authentication: the holder really possesses the credential.

### Predicate mode

Same outputs as disclosure mode, plus:

- **Predicate result** (true / false). No underlying values leak.

### Never leaked (in either mode)

- The issuer's public key or identity (see "Trust model" below).
- Undisclosed claims, their hashes, or their salts.
- Device private key.
- Anything outside what the verifier explicitly asked for.

## Value normalization

Claim values are extracted from the authenticated preimage and packed
into single field elements so predicates can compare them with simple
`≤`, `≥`, `==`:

| Claim type (`valueType`) | Normalized form |
| ------------------------ | --------------- |
| `0` Date (`YYYY-MM-DD`) | `YYYYMMDD` integer (e.g. `19900715`) |
| `1` String | Base-256 LSB-first packed bytes (e.g. `"CA"` → `16707`) |
| `2` Integer | ASCII decimal digits → field element |
| `3` Reveal-digest | SHA-256 of the value bytes, truncated to 248 bits |

`valueType` must be one of these four values; any other value causes
the active claim to fail verification (no silent zero).

Dates use the same `YYYYMMDD` form as the JWT circuit's `iso_date`
format, so mdoc and JWT credentials are directly comparable in mixed
predicates.

## Encoding constraints (caller contract)

The protocol assumes the wallet produces inputs that satisfy the
following. Violations yield either proof failure or, for the
collision case, an ambiguous normalized value. The wallet SDK is
responsible for enforcing them; the circuit does not re-check them.

- **`digestID < 24`.** An mdoc digest entry is matched by pattern
  `[digestID, 0x58, 0x20, <32-byte hash>]`. CBOR encodes unsigned
  integers 0–23 in a single byte, so the pattern collapses for larger
  IDs. Real-world mDL namespaces stay well under 24.
- **String length ≤ 31 bytes.** Base-256 packing into a single field
  element is injective only up to ~31 bytes. Longer strings can
  collide; the wallet must reject or truncate.
- **Integer bytes are ASCII digits (`0x30`–`0x39`).** The decimal
  accumulator does not range-check the source bytes; non-digit bytes
  produce a garbage field element.
- **`valueEnd ≤ preimageLength`** and **`valueEnd - valueStart ≤
  maxValueLen`.** The circuit enforces both; the SDK must set
  positions consistently with the actual CBOR byte ranges.

## Layered responsibilities

| Layer                    | Owns                                                               |
| ------------------------ | ------------------------------------------------------------------ |
| Transport (BLE, NFC, QR) | Nonce exchange, session transcript                                 |
| Crypto                   | Signature verification, hashing, device binding                    |
| Policy                   | Trust list, doctype / namespace expectations, predicate definition |
| UX                       | Shows the holder what's being asked and the verifier the result    |

## Failure modes the spec must prevent

- Forged credential. Check 1.
- Cross-doctype attack (passport MSO presented as an mDL). Check 2.
- Wrong-namespace attack (claim from a different namespace passed off
  as ISO mDL). Check 3.
- Expired or not-yet-valid credential used. Checks 4, 5.
- Revoked credential still accepted. Check 6.
- Holder lies about a claim value. Checks 7, 8, 9.
- Value-position forgery (pointing at bytes other than the real
  `elementValue`). Check 8.
- Dictionary attack on low-entropy claims. Check 10.
- Credential theft or replay from another device. Checks 11, 12.
- Replay of a prior session. Check 13.
- Predicate gaming via crafted inputs. Check 14 plus all of the above.

## What ZK changes vs. plain mDL

Plain mDL exposes disclosed claim values directly. With zero knowledge
you can:

- Replace Check 14's disclosed inputs with a proof that the predicate
  holds. The value itself stays hidden.
- Hide which specific claims are being presented, if combined with a
  commitment layer on identifiers.

ZK does not replace any check above. It only changes what leaves the
holder's device. The checks themselves are the same.

## Optional extensions

- **In-proof issuer trust.** Make the issuer public key (or its hash)
  a public output, and have the verifier match it against an IACA
  trust list. For full anonymity among trusted issuers, replace the
  exposed key with a Merkle membership proof against an IACA root
  (public input). See "Trust model" for why this isn't in the default
  flow.
- **In-circuit `now` check.** Pass `now` as a public input and enforce
  Checks 4 and 5 inside the circuit, so the verifier does not need to
  trust their own clock relative to an extracted date.
- **Revocation (Check 6) in-circuit.** Prove non-membership in a
  revocation accumulator instead of relying on an off-circuit status
  lookup.
- **Device-key unlinkability.** Commit to the device key with a
  per-session blinding factor so the same credential is not trivially
  linkable across presentations.

## Trust model

The ZK proof does **not** expose the issuer's public key. It only
proves that some key was used to sign the MSO, and that the prover
knew that key and a matching signature. Choosing the right key, one
that belongs to a legitimate issuer, is entirely the prover's
responsibility.

In deployment, this trust is carried by the layer that builds the
proof:

1. **The holder's wallet** holds the issuer's public key as part of
   provisioning the mDL. The wallet only ever builds proofs against
   genuine issuer-signed credentials it received through the official
   issuance flow.
2. **The verifier** trusts the wallet (through platform attestation,
   app signing, or out-of-band configuration) rather than through any
   signal in the proof itself.

Consequences and limits:

- A malicious holder with a self-generated key could construct a proof
  that passes every on-chip check but doesn't correspond to a real
  credential. The verifier catches this only via the
  wallet-attestation channel, not the proof.
- The verifier cannot tell which issuer signed the credential from the
  proof alone. For use cases that need that (multi-issuer registries,
  compliance reporting), use the in-proof trust extension described
  above.

X.509 chain validation inside a SNARK is impractical: parsing ASN.1,
walking arbitrary cert chain depths, and verifying ECDSA at each level
costs far more than the protocol saves. Either do trust out-of-band
(current approach) or do Merkle membership against a pre-validated
trust root (cheap in-circuit). Not full chain validation.
