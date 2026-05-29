/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import cbor from "cbor";
import { beforeAll, describe, expect, test } from "vitest";

import { parseMdoc } from "@/logic/mdoc";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { CredentialRequestResponse } from "@/step/issuance";

const { decode, Tagged } = cbor;

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("MdocDataModel");

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Mdoc CBOR Data Model Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let credentialResponse: CredentialRequestResponse;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      const result = await orchestrator.issuance();
      assertIssuanceFlowSuccess(result);
      credentialResponse = result.credentialResponse;
    });

    useTestSummary(baseLog, testConfig.name);

    // -----------------------------------------------------------------------
    // Helper: extract mdoc credentials from the issuance response
    // -----------------------------------------------------------------------

    function getMdocCredentials(): { raw: Buffer }[] {
      const result: { raw: Buffer }[] = [];
      for (const credObj of credentialResponse.response?.credentials ?? []) {
        try {
          const raw = Buffer.from(credObj.credential, "base64url");
          // parseMdoc throws for non-mdoc bytes — use it as a guard
          parseMdoc(raw);
          result.push({ raw });
        } catch {
          // non-mdoc credential (e.g. SD-JWT) — skip silently
        }
      }
      return result;
    }

    // =======================================================================
    // CI_137 — Mdoc Credential CBOR Encoding Validation
    // =======================================================================

    test("CI_137: Mdoc Credential Format | Data elements are CBOR-encoded per RFC 8949 / ISO 18013-5", async () => {
      const log = baseLog.withTag("CI_137");
      const DESCRIPTION =
        "Mdoc credential bytes are well-formed CBOR: mandatory top-level keys present, nameSpaces entries are Tag 24 byte strings that re-decode to valid IssuerSignedItem maps, and issuerAuth protected header is a CBOR-encoded alg map";

      log.start(
        "Conformance test: mdoc CBOR encoding per RFC 8949 / ISO 18013-5",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_137 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          // -----------------------------------------------------------------
          // 1. Raw bytes are valid CBOR (RFC 8949 §3)
          // -----------------------------------------------------------------
          // Decode directly — before parseMdoc — so raw cbor.Tagged instances
          // are still present in nameSpaces.
          const decoded = decode(raw) as Record<string, unknown>;

          expect(
            decoded,
            "CBOR decode must succeed on raw credential bytes",
          ).toBeDefined();

          // -----------------------------------------------------------------
          // 2. Top-level structure is a CBOR map with mandatory keys
          //    (ISO 18013-5 §8.3.2.1)
          // -----------------------------------------------------------------
          expect(
            typeof decoded === "object" && decoded !== null,
            "Top-level CBOR item must be a map",
          ).toBe(true);

          expect(
            "issuerAuth" in decoded,
            "CBOR map must contain issuerAuth key",
          ).toBe(true);

          expect(
            "nameSpaces" in decoded,
            "CBOR map must contain nameSpaces key",
          ).toBe(true);

          // -----------------------------------------------------------------
          // 3. nameSpaces is a CBOR map with at least one namespace
          //    (ISO 18013-5 §8.3.2.1.2)
          // -----------------------------------------------------------------
          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          const nsKeys = Object.keys(nameSpaces);
          expect(
            nsKeys.length,
            "nameSpaces must contain at least one namespace entry",
          ).toBeGreaterThan(0);

          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

          // -----------------------------------------------------------------
          // 4 & 5. Each namespace entry is an array of CBOR Tag 24 items,
          //        and each Tag 24 payload re-decodes to a valid IssuerSignedItem
          //        (ISO 18013-5 §9.1.2, RFC 8949 §3.4, ISO 18013-5 Table 2)
          // -----------------------------------------------------------------
          for (const [namespaceName, items] of Object.entries(nameSpaces)) {
            expect(
              Array.isArray(items),
              `nameSpaces["${namespaceName}"] must be an array`,
            ).toBe(true);

            for (const item of items as unknown[]) {
              expect(
                item instanceof Tagged,
                `Each IssuerSignedItemBytes in "${namespaceName}" must be a CBOR Tagged item`,
              ).toBe(true);

              const tagged = item as cbor.Tagged;

              expect(
                tagged.tag,
                `IssuerSignedItemBytes tag must be 24 (embedded CBOR) per RFC 8949 §3.4 / ISO 18013-5 §9.1.2`,
              ).toBe(24);

              expect(
                tagged.value instanceof Uint8Array ||
                  Buffer.isBuffer(tagged.value),
                "Tag 24 content must be a byte string",
              ).toBe(true);

              // 5. Tag 24 payload re-decodes to a valid IssuerSignedItem map
              const itemBytes = Buffer.isBuffer(tagged.value)
                ? tagged.value
                : Buffer.from(tagged.value as Uint8Array);

              const signedItem = decode(itemBytes) as Record<string, unknown>;

              expect(
                typeof signedItem === "object" && signedItem !== null,
                "IssuerSignedItemBytes payload must decode to a CBOR map",
              ).toBe(true);

              // ISO 18013-5 Table 2: required fields of IssuerSignedItem
              expect(
                "digestID" in signedItem,
                "IssuerSignedItem must contain digestID",
              ).toBe(true);

              expect(
                "random" in signedItem,
                "IssuerSignedItem must contain random",
              ).toBe(true);

              expect(
                "elementIdentifier" in signedItem,
                "IssuerSignedItem must contain elementIdentifier",
              ).toBe(true);

              expect(
                "elementValue" in signedItem,
                "IssuerSignedItem must contain elementValue",
              ).toBe(true);

              expect(
                typeof signedItem["digestID"],
                "digestID must be a CBOR unsigned integer",
              ).toBe("number");

              expect(
                typeof signedItem["elementIdentifier"],
                "elementIdentifier must be a CBOR text string",
              ).toBe("string");

              log.debug(
                `  ✓ ${namespaceName}[${String(signedItem["elementIdentifier"])}] Tag 24 → IssuerSignedItem valid`,
              );
            }
          }

          // -----------------------------------------------------------------
          // 6. issuerAuth protected header is a CBOR-encoded byte string
          //    containing the alg parameter (ISO 18013-5 §9.1.2.4, RFC 9052)
          // -----------------------------------------------------------------
          const issuerAuth = decoded["issuerAuth"] as unknown[];

          expect(
            Array.isArray(issuerAuth),
            "issuerAuth must be a CBOR array (COSE_Sign1)",
          ).toBe(true);

          expect(
            issuerAuth.length,
            "COSE_Sign1 array must have exactly 4 elements",
          ).toBe(4);

          const protectedHeader = issuerAuth[0];

          expect(
            protectedHeader instanceof Uint8Array ||
              Buffer.isBuffer(protectedHeader),
            "issuerAuth[0] (protected header) must be a CBOR byte string",
          ).toBe(true);

          const protectedHeaderMap = decode(
            Buffer.isBuffer(protectedHeader)
              ? protectedHeader
              : Buffer.from(protectedHeader as Uint8Array),
          ) as Record<number | string, unknown>;

          expect(
            typeof protectedHeaderMap === "object" &&
              protectedHeaderMap !== null,
            "Protected header byte string must decode to a valid CBOR map",
          ).toBe(true);

          // COSE header label 1 = alg (RFC 9052 §3.1)
          const algLabel = 1;
          expect(
            algLabel in protectedHeaderMap,
            "Protected header CBOR map must contain the alg parameter (label 1)",
          ).toBe(true);

          log.debug(
            `  ✓ issuerAuth COSE_Sign1 protected header valid, alg label present`,
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
