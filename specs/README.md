# zkID Specifications

This directory hosts protocol specifications maintained alongside the zkID
reference implementation.

| # | Spec | Status | Summary |
| - | --- | --- | --- |
| 1 | [OPENAC-CORE](./1-openac-core/README.md) | raw | OpenAC core protocol: two-phase `Prepare` / `Show` anonymous-credential presentation with the current `SD-JWT-P256` profile. |
| 2 | [ZK-HUMAN-VERIFICATION](./2-zk-human-verification/README.md) | raw | ZK-based one-time "verified human" status for online forums, with a deterministic nullifier. |
| 3 | [ZK-AGE-ELIGIBILITY](./3-zk-age-eligibility/README.md) | raw | Wallet-based age-eligibility verification, profiled on top of OpenAC. Initial scope: Driver License for alcohol-purchase gating. |

## Change Process

Specs in this directory are governed by the
[1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1)
change-control process. Status promotion (`raw` → `draft` → ...) follows the
COSS lifecycle.

## Editorial History

Specs 1–3 were initially incubated in `privacy-ethereum/zkspecs` and moved
to this repository so they sit alongside the implementations they describe:

- `1/OPENAC-CORE` — previously drafted as `zkspecs#23` (and earlier `zkspecs#21`).
- `2/ZK-HUMAN-VERIFICATION` — merged at `zkspecs` `specs/5`; updates carried over from `zkspecs#20`.
- `3/ZK-AGE-ELIGIBILITY` — previously drafted as `zkspecs#19`.
