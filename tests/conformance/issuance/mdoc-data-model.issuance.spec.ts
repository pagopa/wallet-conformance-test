/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import cbor from "cbor";
import { createHash, timingSafeEqual } from "node:crypto";
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
        "Mdoc credential bytes are well-formed CBOR: top-level item is a CBOR map, nameSpaces entries are Tag 24 byte strings that re-decode to valid IssuerSignedItem maps, and issuerAuth protected header is a CBOR-encoded alg map";

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
          // 2. Top-level structure is a CBOR map (ISO 18013-5 §8.3.2.1)
          // -----------------------------------------------------------------
          expect(
            typeof decoded === "object" && decoded !== null,
            "Top-level CBOR item must be a map",
          ).toBe(true);

          // -----------------------------------------------------------------
          // 3. nameSpaces entries are CBOR Tag 24 items that re-decode to
          //    valid IssuerSignedItem maps
          //    (ISO 18013-5 §9.1.2, RFC 8949 §3.4, ISO 18013-5 Table 2)
          // -----------------------------------------------------------------
          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          const nsKeys = Object.keys(nameSpaces);
          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

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

              // Tag 24 payload re-decodes to a valid IssuerSignedItem map
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
          // 4. issuerAuth protected header is a CBOR-encoded byte string
          //    containing the alg parameter (ISO 18013-5 §9.1.2.4, RFC 9052)
          // -----------------------------------------------------------------
          const issuerAuth = decoded["issuerAuth"] as unknown[];

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

    // =======================================================================
    // CI_138 — Mdoc Component Structure Organisation
    // =======================================================================

    test("CI_138: Mdoc Component Structure | Digital Credential is structured into distinct nameSpaces and issuerAuth components per IT-Wallet spec", async () => {
      const log = baseLog.withTag("CI_138");
      const DESCRIPTION =
        "Mdoc Digital Credential is properly structured into its two distinct components — nameSpaces (attribute data) and issuerAuth (cryptographic proof/MSO) — with correct types, internal completeness, and MSO valueDigests cross-referencing nameSpaces";

      log.start(
        "Conformance test: mdoc component structure per IT-Wallet spec / ISO 18013-5 §9.1.2.4",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_138 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          const decoded = decode(raw) as Record<string, unknown>;

          // -----------------------------------------------------------------
          // Layer A — Top-level distinct components
          // (IT-Wallet spec: "struttura gli Attestati Elettronici in
          //  componenti distinti: namespaces e prova crittografica")
          // -----------------------------------------------------------------

          expect(
            "nameSpaces" in decoded,
            "CBOR map must contain nameSpaces key",
          ).toBe(true);

          expect(
            "issuerAuth" in decoded,
            "CBOR map must contain issuerAuth key",
          ).toBe(true);

          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          expect(
            typeof nameSpaces === "object" &&
              nameSpaces !== null &&
              !Array.isArray(nameSpaces),
            "nameSpaces value must be a CBOR map",
          ).toBe(true);

          const nsKeys = Object.keys(nameSpaces);
          expect(
            nsKeys.length,
            "nameSpaces must contain at least one namespace entry",
          ).toBeGreaterThan(0);

          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

          const issuerAuth = decoded["issuerAuth"] as unknown[];

          expect(
            Array.isArray(issuerAuth),
            "issuerAuth must be a CBOR array (COSE_Sign1)",
          ).toBe(true);

          expect(
            issuerAuth.length,
            "COSE_Sign1 array must have exactly 4 elements",
          ).toBe(4);

          // -----------------------------------------------------------------
          // Layer B — issuerAuth component completeness
          // (ISO 18013-5 §9.1.2.4, RFC 9052, RFC 9360)
          // -----------------------------------------------------------------

          // issuerAuth[1]: unprotected header — must be a CBOR map containing
          // label 33 (x5chain) per RFC 9360 for X.509-based issuance
          const unprotectedHeader = issuerAuth[1];

          expect(
            unprotectedHeader !== null && typeof unprotectedHeader === "object",
            "issuerAuth[1] (unprotected header) must be a CBOR map",
          ).toBe(true);

          const x5chainLabel = 33;
          const unprotectedHas33 =
            unprotectedHeader instanceof Map
              ? unprotectedHeader.has(x5chainLabel)
              : x5chainLabel in
                (unprotectedHeader as Record<number | string, unknown>);

          expect(
            unprotectedHas33,
            "issuerAuth[1] unprotected header must contain x5chain (label 33) per RFC 9360",
          ).toBe(true);

          log.debug(
            `  ✓ issuerAuth[1] unprotected header contains x5chain (label 33)`,
          );

          // issuerAuth[2]: payload — must be a byte string (COSE payload bstr)
          const payloadBytes = issuerAuth[2];

          expect(
            payloadBytes instanceof Uint8Array || Buffer.isBuffer(payloadBytes),
            "issuerAuth[2] (payload) must be a byte string (Uint8Array / Buffer)",
          ).toBe(true);

          // Payload bstr wraps CBOR Tag 24 containing the MobileSecurityObject
          // (ISO 18013-5 §9.1.2.4, RFC 8949 §3.4)
          const payloadTagged = decode(
            Buffer.isBuffer(payloadBytes)
              ? payloadBytes
              : Buffer.from(payloadBytes as Uint8Array),
          ) as cbor.Tagged;

          expect(
            payloadTagged.tag,
            "issuerAuth payload must be wrapped in CBOR Tag 24 (embedded CBOR per RFC 8949 §3.4)",
          ).toBe(24);

          // Inner bytes decode to the MobileSecurityObject CBOR map
          const msoBytes = Buffer.isBuffer(payloadTagged.value)
            ? payloadTagged.value
            : Buffer.from(payloadTagged.value as Uint8Array);

          const mso = decode(msoBytes) as
            | Map<string, unknown>
            | Record<string, unknown>;

          expect(
            mso !== null && typeof mso === "object",
            "Tag 24 inner bytes must decode to a CBOR map (MobileSecurityObject)",
          ).toBe(true);

          // Helper to check MSO field presence regardless of Map vs plain object
          const msoHas = (key: string): boolean =>
            mso instanceof Map ? mso.has(key) : key in mso;

          const msoGet = (key: string): unknown =>
            mso instanceof Map
              ? mso.get(key)
              : (mso as Record<string, unknown>)[key];

          // ISO 18013-5 §9.1.2.4: mandatory MSO fields
          expect(
            msoHas("docType"),
            "MSO must contain mandatory field docType",
          ).toBe(true);
          expect(
            msoHas("version"),
            "MSO must contain mandatory field version",
          ).toBe(true);
          expect(
            msoHas("validityInfo"),
            "MSO must contain mandatory field validityInfo",
          ).toBe(true);
          expect(
            msoHas("digestAlgorithm"),
            "MSO must contain mandatory field digestAlgorithm",
          ).toBe(true);
          expect(
            msoHas("valueDigests"),
            "MSO must contain mandatory field valueDigests",
          ).toBe(true);
          expect(
            msoHas("deviceKeyInfo"),
            "MSO must contain mandatory field deviceKeyInfo",
          ).toBe(true);

          // validityInfo must contain validUntil (ISO 18013-5 §9.1.2.4)
          const validityInfo = msoGet("validityInfo") as
            | Map<string, unknown>
            | null
            | Record<string, unknown>
            | undefined;

          expect(
            validityInfo !== null && typeof validityInfo === "object",
            "MSO validityInfo must be a map",
          ).toBe(true);

          const validityInfoHas = (key: string): boolean =>
            validityInfo instanceof Map
              ? validityInfo.has(key)
              : key in (validityInfo as Record<string, unknown>);

          expect(
            validityInfoHas("validUntil"),
            "MSO validityInfo must contain validUntil",
          ).toBe(true);

          log.debug(`  ✓ MSO validityInfo.validUntil present`);

          // deviceKeyInfo must contain deviceKey
          const deviceKeyInfo = msoGet("deviceKeyInfo") as
            | Map<string, unknown>
            | null
            | Record<string, unknown>
            | undefined;

          expect(
            deviceKeyInfo !== null && typeof deviceKeyInfo === "object",
            "MSO deviceKeyInfo must be a map",
          ).toBe(true);

          const deviceKeyInfoHas = (key: string): boolean =>
            deviceKeyInfo instanceof Map
              ? deviceKeyInfo.has(key)
              : key in (deviceKeyInfo as Record<string, unknown>);

          expect(
            deviceKeyInfoHas("deviceKey"),
            "MSO deviceKeyInfo must contain deviceKey",
          ).toBe(true);

          log.debug(`  ✓ MSO deviceKeyInfo.deviceKey present`);

          // issuerAuth[3]: signature — must be a byte string
          const signatureBytes = issuerAuth[3];

          expect(
            signatureBytes instanceof Uint8Array ||
              Buffer.isBuffer(signatureBytes),
            "issuerAuth[3] (signature) must be a byte string",
          ).toBe(true);

          log.debug(`  ✓ issuerAuth[3] signature bytes present`);

          // -----------------------------------------------------------------
          // Layer C — Cross-link: nameSpaces ↔ valueDigests
          // (IT-Wallet spec: "Il MSO memorizza in modo sicuro i digest
          //  crittografici degli attributi all'interno dei nameSpaces")
          // -----------------------------------------------------------------
          const valueDigests = msoGet("valueDigests") as
            | Map<string, unknown>
            | Record<string, unknown>;

          expect(
            valueDigests !== null && typeof valueDigests === "object",
            "MSO valueDigests must be a map",
          ).toBe(true);

          for (const nsKey of nsKeys) {
            const vdHas =
              valueDigests instanceof Map
                ? valueDigests.has(nsKey)
                : nsKey in (valueDigests as Record<string, unknown>);

            expect(
              vdHas,
              `MSO valueDigests must contain an entry for namespace "${nsKey}" (cross-link with nameSpaces)`,
            ).toBe(true);

            log.debug(
              `  ✓ valueDigests contains cross-link for namespace "${nsKey}"`,
            );
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_139 — Mdoc Credential MSO Digest Integrity Validation
    // =======================================================================

    test("CI_139: Mdoc Credential MSO Digest Integrity | The MSO correctly stores cryptographic digests of attributes within nameSpaces, enabling Relying Parties to validate disclosed attributes against corresponding digestID values while maintaining privacy of undisclosed information", async () => {
      const log = baseLog.withTag("CI_139");
      const DESCRIPTION =
        "Mdoc Credential MSO Digest Integrity | The MSO correctly stores cryptographic digests of attributes within nameSpaces, enabling Relying Parties to validate disclosed attributes against corresponding digestID values while maintaining privacy of undisclosed information";

      log.start(
        "Conformance test: MSO digest integrity per ISO 18013-5 §9.1.2.4, §9.1.2.5, §9.3.1",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_139 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          const decoded = decode(raw) as Record<string, unknown>;

          // ---------------------------------------------------------------
          // Decode MSO (same path as CI_138)
          // ---------------------------------------------------------------
          const issuerAuth = decoded["issuerAuth"] as unknown[];
          const payloadBytes = issuerAuth[2];

          const payloadTagged = decode(
            Buffer.isBuffer(payloadBytes)
              ? payloadBytes
              : Buffer.from(payloadBytes as Uint8Array),
          ) as cbor.Tagged;

          const msoBytes = Buffer.isBuffer(payloadTagged.value)
            ? payloadTagged.value
            : Buffer.from(payloadTagged.value as Uint8Array);

          const mso = decode(msoBytes) as
            | Map<string, unknown>
            | Record<string, unknown>;

          const msoGet = (key: string): unknown =>
            mso instanceof Map
              ? mso.get(key)
              : (mso as Record<string, unknown>)[key];

          const digestAlgorithmRaw = msoGet("digestAlgorithm") as string;

          // Normalise "SHA-256" → "sha256" for Node crypto
          const digestAlgorithm = digestAlgorithmRaw
            .toLowerCase()
            .replace("-", "");

          log.debug(
            `  digestAlgorithm: ${digestAlgorithmRaw} → ${digestAlgorithm}`,
          );

          const valueDigests = msoGet("valueDigests") as
            | Map<string, unknown>
            | Record<string, unknown>;

          // Helper for Map-or-plain-object access on valueDigests entries
          const vdGet = (
            container: Map<unknown, unknown> | Record<number | string, unknown>,
            key: unknown,
          ): unknown =>
            container instanceof Map
              ? container.get(key)
              : (container as Record<number | string, unknown>)[
                  key as number | string
                ];

          const vdHasKey = (
            container: Map<unknown, unknown> | Record<number | string, unknown>,
            key: unknown,
          ): boolean =>
            container instanceof Map
              ? container.has(key)
              : (key as number | string) in
                (container as Record<number | string, unknown>);

          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          for (const [ns, items] of Object.entries(nameSpaces)) {
            const nsDigests = (
              valueDigests instanceof Map
                ? valueDigests.get(ns)
                : (valueDigests as Record<string, unknown>)[ns]
            ) as Map<unknown, unknown> | Record<number | string, unknown>;

            const seenDigestIDs = new Set<number>();

            for (const taggedItem of items as cbor.Tagged[]) {
              // The raw bytes of the Tag 24 bstr content — this is the
              // IssuerSignedItemBytes as defined in ISO 18013-5 §9.1.2.5
              const itemRawBytes = Buffer.isBuffer(taggedItem.value)
                ? taggedItem.value
                : Buffer.from(taggedItem.value as Uint8Array);

              const itemMap = decode(itemRawBytes) as Record<string, unknown>;

              // -----------------------------------------------------------
              // A. random field is ≥ 16 bytes (ISO 18013-5 §9.1.2.5)
              // -----------------------------------------------------------
              const random = itemMap["random"] as Buffer | Uint8Array;
              const randomBuf = Buffer.isBuffer(random)
                ? random
                : Buffer.from(random);

              expect(
                randomBuf.length >= 16,
                `IssuerSignedItem.random in namespace "${ns}" must be at least 16 bytes (ISO 18013-5 §9.1.2.5), got ${randomBuf.length}`,
              ).toBe(true);

              // -----------------------------------------------------------
              // B. digestID values are unique per namespace (ISO 18013-5 §9.1.2.5)
              // -----------------------------------------------------------
              const digestID = itemMap["digestID"] as number;

              expect(
                !seenDigestIDs.has(digestID),
                `digestID ${digestID} in namespace "${ns}" must be unique per namespace (ISO 18013-5 §9.1.2.5)`,
              ).toBe(true);

              seenDigestIDs.add(digestID);

              // -----------------------------------------------------------
              // C. digestID exists in valueDigests[ns] (ISO 18013-5 §9.1.2.5 + §9.3.1)
              // -----------------------------------------------------------
              expect(
                vdHasKey(nsDigests, digestID) ||
                  vdHasKey(nsDigests, String(digestID)),
                `valueDigests["${ns}"] must contain an entry for digestID ${digestID} (ISO 18013-5 §9.1.2.5 + §9.3.1)`,
              ).toBe(true);

              // -----------------------------------------------------------
              // D. Hash(IssuerSignedItemBytes) === valueDigests[ns][digestID]
              //    (ISO 18013-5 §9.1.2.4 + §9.3.1)
              //    IMPORTANT: hash taggedItem.value (the raw Tag 24 bstr content),
              //    NOT a re-encoding of the decoded map.
              // -----------------------------------------------------------
              const computed = createHash(digestAlgorithm)
                .update(itemRawBytes)
                .digest();

              const expectedRaw =
                vdGet(nsDigests, digestID) ??
                vdGet(nsDigests, String(digestID));

              const expected = Buffer.isBuffer(expectedRaw)
                ? expectedRaw
                : Buffer.from(expectedRaw as Uint8Array);

              expect(
                computed.length === expected.length &&
                  timingSafeEqual(computed, expected),
                `${digestAlgorithm}(IssuerSignedItemBytes) must match valueDigests["${ns}"][${digestID}] (ISO 18013-5 §9.1.2.4 + §9.3.1)`,
              ).toBe(true);

              log.debug(
                `  ✓ ${ns}[digestID=${digestID}] digest integrity verified`,
              );
            }
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_140 — Mdoc-CBOR Digital Credential Required Structure
    // =======================================================================

    test("CI_140: Mdoc Credential Format | The mdoc-CBOR Digital Credential successfully conforms to the required structure (nameSpaces map per ISO 18013-5 §8.3.2.1.2 and issuerAuth COSE_Sign1 per ISO 18013-5 §9.1.2.4)", async () => {
      const log = baseLog.withTag("CI_140");
      const DESCRIPTION =
        "The mdoc-CBOR Digital Credential successfully conforms to the required structure as specified in the compliance table: nameSpaces is a CBOR map of namespaces containing the defined data elements (ISO 18013-5 §8.3.2.1.2), and issuerAuth is a COSE_Sign1 structure carrying the Mobile Security Object (MSO) issued by the Credential Issuer (ISO 18013-5 §9.1.2.4)";

      log.start(
        "Conformance test: mdoc-CBOR required structure per ISO 18013-5 §8.3.2.1.2 / §9.1.2.4",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_140 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          const decoded = decode(raw) as Record<string, unknown>;

          // -----------------------------------------------------------------
          // Top-level IssuerSigned must be a CBOR map containing the two
          // required compliance-table parameters: nameSpaces and issuerAuth.
          // -----------------------------------------------------------------
          expect(
            typeof decoded === "object" && decoded !== null,
            "IssuerSigned top-level CBOR item must be a map",
          ).toBe(true);

          // -----------------------------------------------------------------
          // Compliance row 1 — nameSpaces (ISO 18013-5 §8.3.2.1.2)
          // "(map). The namespaces within which the data elements are defined.
          //  A Digital Credential MAY include multiple namespaces."
          // -----------------------------------------------------------------
          expect(
            "nameSpaces" in decoded,
            "IssuerSigned must contain the required parameter `nameSpaces` (ISO 18013-5 §8.3.2.1.2)",
          ).toBe(true);

          const nameSpacesRaw = decoded["nameSpaces"];

          expect(
            nameSpacesRaw !== null &&
              typeof nameSpacesRaw === "object" &&
              !Array.isArray(nameSpacesRaw),
            "`nameSpaces` must be a CBOR map (ISO 18013-5 §8.3.2.1.2)",
          ).toBe(true);

          const nameSpaces = nameSpacesRaw as Record<string, unknown>;
          const nsKeys = Object.keys(nameSpaces);

          expect(
            nsKeys.length,
            "`nameSpaces` map must contain at least one namespace entry defining data elements (ISO 18013-5 §8.3.2.1.2)",
          ).toBeGreaterThan(0);

          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

          for (const [namespaceName, items] of Object.entries(nameSpaces)) {
            expect(
              Array.isArray(items),
              `nameSpaces["${namespaceName}"] must be a CBOR array of data elements (IssuerSignedItemBytes)`,
            ).toBe(true);

            expect(
              (items as unknown[]).length,
              `nameSpaces["${namespaceName}"] must declare at least one data element`,
            ).toBeGreaterThan(0);
          }

          // -----------------------------------------------------------------
          // Compliance row 2 — issuerAuth (ISO 18013-5 §9.1.2.4)
          // "(COSE_Sign1). Contains Mobile Security Object (MSO),
          //  a COSE Sign1 Document, issued by the Credential Issuer."
          // -----------------------------------------------------------------
          expect(
            "issuerAuth" in decoded,
            "IssuerSigned must contain the required parameter `issuerAuth` (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);

          const issuerAuth = decoded["issuerAuth"];

          // COSE_Sign1 is encoded as an untagged 4-tuple CBOR array
          // [protected, unprotected, payload, signature] per RFC 9052 §4.2.
          expect(
            Array.isArray(issuerAuth),
            "`issuerAuth` must be a CBOR array encoding a COSE_Sign1 structure (RFC 9052 §4.2 / ISO 18013-5 §9.1.2.4)",
          ).toBe(true);

          const issuerAuthArr = issuerAuth as unknown[];

          expect(
            issuerAuthArr.length,
            "COSE_Sign1 must be a 4-tuple: [protected, unprotected, payload, signature] (RFC 9052 §4.2)",
          ).toBe(4);

          const [protectedHeader, unprotectedHeader, payload, signature] =
            issuerAuthArr;

          expect(
            protectedHeader instanceof Uint8Array ||
              Buffer.isBuffer(protectedHeader),
            "COSE_Sign1[0] (protected header) must be a CBOR byte string (RFC 9052 §3)",
          ).toBe(true);

          expect(
            unprotectedHeader !== null && typeof unprotectedHeader === "object",
            "COSE_Sign1[1] (unprotected header) must be a CBOR map (RFC 9052 §3)",
          ).toBe(true);

          expect(
            payload instanceof Uint8Array || Buffer.isBuffer(payload),
            "COSE_Sign1[2] (payload) must be a CBOR byte string carrying the MSO (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);

          expect(
            signature instanceof Uint8Array || Buffer.isBuffer(signature),
            "COSE_Sign1[3] (signature) must be a CBOR byte string (RFC 9052 §4.2)",
          ).toBe(true);

          // The payload byte string MUST carry the MSO. Per ISO 18013-5
          // §9.1.2.4 the MSO is wrapped in CBOR Tag 24 (embedded CBOR,
          // RFC 8949 §3.4) and decodes to a CBOR map (MobileSecurityObject).
          const payloadBytes = Buffer.isBuffer(payload)
            ? payload
            : Buffer.from(payload as Uint8Array);

          const payloadTagged = decode(payloadBytes) as cbor.Tagged;

          expect(
            payloadTagged instanceof Tagged && payloadTagged.tag === 24,
            "issuerAuth payload must wrap the MSO in CBOR Tag 24 (ISO 18013-5 §9.1.2.4 / RFC 8949 §3.4)",
          ).toBe(true);

          const msoBytes = Buffer.isBuffer(payloadTagged.value)
            ? payloadTagged.value
            : Buffer.from(payloadTagged.value as Uint8Array);

          const mso = decode(msoBytes) as
            | Map<string, unknown>
            | Record<string, unknown>;

          expect(
            mso !== null && typeof mso === "object",
            "issuerAuth payload (Tag 24 inner bytes) must decode to a CBOR map (MobileSecurityObject) issued by the Credential Issuer (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);

          const msoSize =
            mso instanceof Map ? mso.size : Object.keys(mso).length;

          expect(
            msoSize,
            "MobileSecurityObject map must be non-empty (ISO 18013-5 §9.1.2.4)",
          ).toBeGreaterThan(0);

          log.debug(
            `  ✓ IssuerSigned conforms: nameSpaces map with ${nsKeys.length} namespace(s) and issuerAuth COSE_Sign1 carrying MSO`,
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
