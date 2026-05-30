# feat: CI_143 — Mdoc IssuerSignedItem contains all required attributes (digestID, random, elementIdentifier, elementValue)

**Type:** enhancement (new conformance test)
**Area:** Credential Issuer conformance / Mdoc data model
**Detail level:** 📋 MORE (standard issue)
**Target file:** `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts`

---

## Overview

Add a new Credential Issuer conformance test `CI_143` to the existing **MdocDataModel** suite. The test validates the IT-Wallet compliance-table requirement:

> Each `IssuerSignedItemBytes` successfully represents the disclosure information for the corresponding digests within the Mobile Security Object and contains all the attributes specified in the compliance table. The `nameSpaces` contains one or more `nameSpace` entries, each identified by a name. Within each `nameSpace`, it includes one or more `IssuerSignedItemBytes`, each encoded as a CBOR byte string with Tag 24 (`#6.24(bstr .cbor)`), which appears as `24(<<…>>)` in diagnostic notation. It represents the disclosure information for each digest within the Mobile Security Object and MUST contain the following attributes:

| Name              | Type    | Description                                                                                                                                | Reference                  |
| ----------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| digestID          | `uint`  | Reference value to one of the `ValueDigests` provided in the Mobile Security Object.                                                       | ISO 18013-5 §9.1.2.5       |
| random            | `bstr`  | Random byte value used as salt for the hash function. MUST be different for each `IssuerSignedItem` and MUST have a minimum length of 16 bytes. | ISO 18013-5 §9.1.2.5       |
| elementIdentifier | `tstr`  | Data element identifier.                                                                                                                   | ISO 18013-5 §8.3.2.1.2.3   |
| elementValue      | `any`   | Data element value.                                                                                                                        | ISO 18013-5 §8.3.2.1.2.3   |

This pins down the **schema contract** for the embedded `IssuerSignedItem` map carried inside every Tag 24 `IssuerSignedItemBytes`.

## Problem Statement / Motivation

The existing suite covers the related compliance rows but none matches CI_143 verbatim:

| Test       | What it asserts on the embedded `IssuerSignedItem` map                                                                                                                       |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CI_137** | Presence of the four keys plus type checks on `digestID` (`number`) and `elementIdentifier` (`string`); bundled together with Tag 24 encoding assertions.                    |
| **CI_139** | `random` length ≥ 16 bytes, uniqueness of `digestID` per namespace, and digest-integrity cross-check against the MSO `valueDigests`.                                         |
| **CI_142** | Encoding-only slice (Tag 24 `bstr .cbor`); does **not** inspect the decoded map.                                                                                             |
| **CI_143** | **Schema-only slice**, verbatim from the compliance-table row: every `IssuerSignedItem` has all four attributes with the correct CBOR types (`uint`, `bstr`, `tstr`, `any`). |

CI_143 isolates the **attribute-level schema contract** from the **encoding contract** (CI_142) and from the **integrity contract** (CI_139). It restates each required attribute and its CBOR type in line with the compliance table, so a missing field or a wrong type fails CI_143 directly with a precise message — without the failure surfacing under a different conformance ID.

Examples that CI_143 (and no other current test) cleanly catches:

- `digestID` encoded as a CBOR negative integer or text string instead of `uint`.
- `random` encoded as a `tstr` (base64 hex) instead of `bstr`.
- `elementIdentifier` encoded as a CBOR integer label.
- `elementValue` missing entirely (the field is `any`, including CBOR `null`, but the **key** must be present).

The compliance-table wording is taken verbatim, matching the row-by-row pattern adopted for CI_140, CI_141 and CI_142.

## Proposed Solution

Add a sixth `test("CI_143: …", …)` block inside the existing `describe` in `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts`, after CI_142, reusing the established harness (`getMdocCredentials()`, skip-on-no-mdoc, `try/finally` + `log.testCompleted`).

Assertions, per credential, per namespace, per `IssuerSignedItemBytes`:

1. Decode the credential and read `decoded["nameSpaces"]` (already validated as a map by CI_140/CI_141).
2. For every Tag 24 element (already validated as Tag 24 by CI_142), decode `tagged.value` to get the `IssuerSignedItem` map.
3. Treat the decoded item as either a `Map<string, unknown>` or a plain object (the `cbor` package returns either depending on the keys — keep the `mapHas` / `mapGet` helper pattern from CI_138/CI_139).
4. Assert each of the **four required keys** is present:
   - `digestID`
   - `random`
   - `elementIdentifier`
   - `elementValue`
5. Assert the CBOR-level type of each:
   - `digestID` — `typeof === "number"` **and** `Number.isInteger` **and** `>= 0` (CBOR `uint`; ISO 18013-5 §9.1.2.5).
   - `random` — `Buffer.isBuffer(v) || v instanceof Uint8Array` (CBOR `bstr`; ISO 18013-5 §9.1.2.5). **Length check is out of scope here** — that belongs to CI_139.
   - `elementIdentifier` — `typeof === "string"` and non-empty (CBOR `tstr`; ISO 18013-5 §8.3.2.1.2.3).
   - `elementValue` — key presence only; `any` per the compliance table. Asserting it is **not `undefined`** is sufficient (CBOR `null` is allowed).

Out of scope (covered elsewhere — do not duplicate):

- Tag 24 wrapping → CI_142.
- `random` length ≥ 16 / `digestID` uniqueness / digest integrity → CI_139.
- nameSpaces map shape / unique keys → CI_140, CI_141.

### Pseudo-code (to be placed inside the `describe` block, after CI_142)

```ts
// tests/conformance/issuance/mdoc-data-model.issuance.spec.ts

test("CI_143: Mdoc Credential Format | Each IssuerSignedItemBytes contains all required attributes (digestID, random, elementIdentifier, elementValue) per ISO 18013-5 §9.1.2.5 / §8.3.2.1.2.3", async () => {
  const log = baseLog.withTag("CI_143");
  const DESCRIPTION =
    "Each IssuerSignedItemBytes successfully represents the disclosure information for the corresponding digests within the MSO and contains all the attributes specified in the compliance table: digestID (uint), random (bstr), elementIdentifier (tstr), elementValue (any)";

  log.start(
    "Conformance test: mdoc IssuerSignedItem required attributes per ISO 18013-5 §9.1.2.5 / §8.3.2.1.2.3",
  );

  let testSuccess = false;
  try {
    const mdocCredentials = getMdocCredentials();
    if (mdocCredentials.length === 0) {
      log.debug("→ CI_143 skipped: no mdoc credentials found");
      testSuccess = true;
      return;
    }

    for (const { raw } of mdocCredentials) {
      const decoded = decode(raw) as Record<string, unknown>;
      const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

      for (const [ns, items] of Object.entries(nameSpaces)) {
        (items as cbor.Tagged[]).forEach((tagged, idx) => {
          // CI_142 already proves: tag === 24 and value is bstr.
          const inner = Buffer.isBuffer(tagged.value)
            ? tagged.value
            : Buffer.from(tagged.value as Uint8Array);

          const item = decode(inner) as
            | Map<string, unknown>
            | Record<string, unknown>;

          // Helpers — match the Map-or-plain-object pattern used by CI_138/CI_139.
          const has = (key: string): boolean =>
            item instanceof Map
              ? item.has(key)
              : key in (item as Record<string, unknown>);
          const get = (key: string): unknown =>
            item instanceof Map
              ? item.get(key)
              : (item as Record<string, unknown>)[key];

          // ----- 1. digestID: uint -----
          expect(
            has("digestID"),
            `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "digestID" (ISO 18013-5 §9.1.2.5)`,
          ).toBe(true);
          const digestID = get("digestID");
          expect(
            typeof digestID === "number" &&
              Number.isInteger(digestID) &&
              (digestID as number) >= 0,
            `digestID in nameSpaces["${ns}"][${idx}] must be a CBOR unsigned integer (uint) per ISO 18013-5 §9.1.2.5, got ${typeof digestID} ${String(digestID)}`,
          ).toBe(true);

          // ----- 2. random: bstr -----
          expect(
            has("random"),
            `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "random" (ISO 18013-5 §9.1.2.5)`,
          ).toBe(true);
          const random = get("random");
          expect(
            Buffer.isBuffer(random) || random instanceof Uint8Array,
            `random in nameSpaces["${ns}"][${idx}] must be a CBOR byte string (bstr) per ISO 18013-5 §9.1.2.5`,
          ).toBe(true);

          // ----- 3. elementIdentifier: tstr -----
          expect(
            has("elementIdentifier"),
            `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "elementIdentifier" (ISO 18013-5 §8.3.2.1.2.3)`,
          ).toBe(true);
          const elementIdentifier = get("elementIdentifier");
          expect(
            typeof elementIdentifier === "string" &&
              elementIdentifier.length > 0,
            `elementIdentifier in nameSpaces["${ns}"][${idx}] must be a non-empty CBOR text string (tstr) per ISO 18013-5 §8.3.2.1.2.3`,
          ).toBe(true);

          // ----- 4. elementValue: any (key MUST be present) -----
          expect(
            has("elementValue"),
            `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "elementValue" (ISO 18013-5 §8.3.2.1.2.3)`,
          ).toBe(true);
          // No type assertion on elementValue: CDDL type is `any`.

          log.debug(
            `  ✓ ${ns}[${idx}] IssuerSignedItem attrs OK (digestID=${String(digestID)}, elementIdentifier="${String(elementIdentifier)}")`,
          );
        });
      }
    }

    testSuccess = true;
  } finally {
    log.testCompleted(DESCRIPTION, testSuccess);
  }
});
```

Imports already present at the top of the file (`cbor` default + `decode` destructure, `WalletIssuanceOrchestratorFlow`, `CredentialRequestResponse`) — no new imports needed.

## Technical Considerations

- **No orchestrator/step changes.** Pure assertion on the existing credential response, in the same module as CI_137–CI_142.
- **Library:** `cbor` (already a dependency). `cbor.decode` is used twice — once on the credential bytes (already validated by CI_140) and once on each Tag 24 inner `bstr` (already validated by CI_142). No new `try/catch` is required because CI_142 enforces inner-CBOR validity before CI_143 runs in the same suite.
- **`Map` vs plain object:** the `cbor` package returns a `Map` when keys are not all string-typed, otherwise a plain object. The four required keys here are text-string keys, so a plain object is the common case — but the helpers (`has`/`get`) cover both for robustness, mirroring `msoHas`/`msoGet` in CI_138/CI_139.
- **Skip behaviour** matches CI_137–CI_142: if no mdoc credentials are present (SD-JWT-only configs), the test logs `→ CI_143 skipped` and returns success.
- **Type safety:** strict mode + `noUncheckedIndexedAccess` — pattern for narrowing decoded values mirrors CI_137 / CI_142.
- **Logging:** `baseLog.withTag("CI_143")`; debug-level success line per element echoing `digestID` + `elementIdentifier` to make failures easy to triage.
- **Intentional overlap with CI_137** (presence of the four keys + `digestID` numeric / `elementIdentifier` string types) — CI_143 keeps a self-contained schema-only assertion so a future cleanup of CI_137 (which mixes encoding + schema) can drop those assertions without losing compliance-row coverage. Same rationale used for CI_142 vs CI_137.

## Acceptance Criteria

- [ ] New `test("CI_143: …", …)` block added inside the existing `describe` in `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts`, **after** CI_142.
- [ ] Test ID literal `CI_143` used in the `test(...)` title and in `baseLog.withTag("CI_143")`.
- [ ] Per `IssuerSignedItem`: assert presence of `digestID`, `random`, `elementIdentifier`, `elementValue`.
- [ ] Type assertions:
  - [ ] `digestID` — `typeof === "number"` && `Number.isInteger` && `>= 0` (CBOR `uint`).
  - [ ] `random` — `Buffer.isBuffer || instanceof Uint8Array` (CBOR `bstr`). No length check (CI_139).
  - [ ] `elementIdentifier` — `typeof === "string"` && non-empty (CBOR `tstr`).
  - [ ] `elementValue` — key presence only (CDDL `any`).
- [ ] Test follows harness conventions: `getMdocCredentials()` skip-path, `let testSuccess = false`, `try/finally`, `log.testCompleted(DESCRIPTION, testSuccess)`.
- [ ] No new imports required; no changes to `src/`.
- [ ] `pnpm pre-commit` passes (format + lint).
- [ ] `pnpm types:check` passes.
- [ ] `pnpm vitest run -t "CI_143"` is green against the local Trust Anchor.
- [ ] `pnpm test:issuance` overall suite remains green.

## Success Metrics

- New test runs and reports pass/fail for every configured issuer returning at least one mdoc credential.
- Skipped (logged) for SD-JWT-only configs.
- Zero changes to orchestrator or step classes (purely additive).

## Dependencies & Risks

- **Dependency:** `cbor` package, already present.
- **Risk:** Wording overlap with CI_137 (presence + `digestID` / `elementIdentifier` type checks). **Mitigation:** documented in this plan and inline; CI_143 is the schema-only slice matching the compliance row verbatim, CI_137 is encoding + schema. Future cleanup may narrow CI_137.
- **Risk:** Issuer emits `digestID` as a CBOR negative integer (e.g. `-1`) — `typeof === "number"` would pass, but `>= 0` would not. Test correctly fails with a precise message. No mitigation required.
- **Risk:** Issuer emits `elementValue` as CBOR `null` — allowed (CDDL `any`). The test only checks key presence, so `null` passes. This is the intended behaviour.
- **Risk:** Issuer emits `random` as a hex `tstr` instead of `bstr` — test correctly fails on the `Buffer`/`Uint8Array` check.

## References

### Internal

- Existing harness: `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts:1` (full file is the template).
- Sibling: presence + partial type checks bundled with encoding: `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts:68` (CI_137).
- Sibling: `random` length, `digestID` uniqueness, digest integrity: `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts:423` (CI_139).
- Sibling: nameSpaces unique naming: `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts:772` (CI_141).
- Sibling: Tag 24 encoding contract (immediately precedes CI_143): `tests/conformance/issuance/mdoc-data-model.issuance.spec.ts:866` (CI_142).
- Mdoc parser: `src/logic/mdoc.ts` (`doc.nameSpaces` shape reference).
- Test harness conventions: `AGENTS.md` → "Testing Conventions".
- Companion plan: `plans/CI_142-mdoc-issuer-signed-item-bytes-tag24.md`.

### External

- ISO/IEC 18013-5:2021 §9.1.2.5 — `IssuerSignedItem` definition (`digestID`, `random`).
- ISO/IEC 18013-5:2021 §8.3.2.1.2.3 — `elementIdentifier` / `elementValue` definitions.
- RFC 8949 §3.1 — CBOR major types (`uint`, `bstr`, `tstr`).
- RFC 8949 §3.4.5.1 — CBOR Tag 24 (Encoded CBOR Data Item).
- IT-Wallet Technical Specifications — Credential Issuer compliance table, row CI_143.
