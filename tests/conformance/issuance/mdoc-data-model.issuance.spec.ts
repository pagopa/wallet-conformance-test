/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { X509Certificate } from "@peculiar/x509";
import cbor from "cbor";
import { createHash, timingSafeEqual } from "node:crypto";
import { beforeAll, describe, expect, test } from "vitest";

import { parseMdoc } from "@/logic/mdoc";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { CredentialRequestResponse } from "@/step/issuance";

const { decode, Tagged } = cbor;
type CborTagged = InstanceType<typeof Tagged>;

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
          // Decode directly — before parseMdoc — so raw cbor.Tagged instances
          // are still present in nameSpaces.
          // Note: top-level CBOR map shape and nameSpaces map/array shape are
          // covered by CI_140; this test focuses on Tag 24 IssuerSignedItem
          // payload structure and the issuerAuth protected header.
          const decoded = decode(raw) as Record<string, unknown>;

          // -----------------------------------------------------------------
          // 1. nameSpaces entries are CBOR Tag 24 items that re-decode to
          //    valid IssuerSignedItem maps
          //    (ISO 18013-5 §9.1.2, RFC 8949 §3.4, ISO 18013-5 Table 2)
          // -----------------------------------------------------------------
          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          const nsKeys = Object.keys(nameSpaces);
          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

          for (const [namespaceName, items] of Object.entries(nameSpaces)) {
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
          // 2. issuerAuth protected header is a CBOR-encoded byte string
          //    containing the alg parameter (ISO 18013-5 §9.1.2.4, RFC 9052)
          // -----------------------------------------------------------------
          const issuerAuth = decoded["issuerAuth"];

          expect(
            Array.isArray(issuerAuth) && (issuerAuth as unknown[]).length >= 4,
            `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
          ).toBe(true);

          const protectedHeader = (issuerAuth as unknown[])[0];

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
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_138 — Mdoc Component Structure Organisation
    // =======================================================================

    test("CI_138: Mdoc Component Structure | Digital Credential issuerAuth unprotected header contains x5chain (label 33) and MSO valueDigests cross-references all nameSpaces entries", async () => {
      const log = baseLog.withTag("CI_138");
      const DESCRIPTION =
        "Mdoc Digital Credential: issuerAuth unprotected header contains x5chain (label 33) per RFC 9360, and MSO valueDigests cross-references all nameSpaces entries";

      log.start(
        "Conformance test: mdoc component structure — x5chain header and nameSpaces ↔ valueDigests cross-link",
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
          //
          // Note: presence of `nameSpaces`/`issuerAuth` keys, nameSpaces map
          // shape and ≥1 entries, issuerAuth as 4-tuple COSE_Sign1 array,
          // payload byte string + Tag 24 wrapper + MSO map, and the
          // signature byte string are all covered by CI_140. This test
          // focuses on: x5chain in unprotected header and the nameSpaces ↔
          // valueDigests cross-link. MSO mandatory field presence is covered
          // by CI_150.
          // -----------------------------------------------------------------

          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;
          const nsKeys = Object.keys(nameSpaces);
          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

          const issuerAuth = decoded["issuerAuth"];

          expect(
            Array.isArray(issuerAuth) && (issuerAuth as unknown[]).length >= 4,
            `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
          ).toBe(true);

          // -----------------------------------------------------------------
          // Layer B — issuerAuth component completeness
          // (ISO 18013-5 §9.1.2.4, RFC 9052, RFC 9360)
          // -----------------------------------------------------------------

          // issuerAuth[1]: unprotected header — must be a CBOR map containing
          // label 33 (x5chain) per RFC 9360 for X.509-based issuance
          const unprotectedHeader = (issuerAuth as unknown[])[1];

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

          // issuerAuth[2]: payload — decode MSO (byte string + Tag 24 wrapper
          // shape are validated by CI_140)
          const payloadBytes = (issuerAuth as unknown[])[2];

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

          // issuerAuth[3] signature byte-string check is covered by CI_140.

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
          const issuerAuth = decoded["issuerAuth"];

          expect(
            Array.isArray(issuerAuth) && (issuerAuth as unknown[]).length >= 4,
            `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
          ).toBe(true);

          const payloadBytes = (issuerAuth as unknown[])[2];

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

    // =======================================================================
    // CI_141 — Mdoc nameSpaces entries uniquely identified by name
    // =======================================================================

    test("CI_141: Mdoc Credential Format | nameSpaces contains one or more entries, each identified by a unique name (ISO 18013-5 §8.3.2.1.2 / §7.1)", async () => {
      const log = baseLog.withTag("CI_141");
      const DESCRIPTION =
        "The nameSpaces map correctly contains one or more nameSpace entries, each properly identified by a unique, non-empty text-string name for organized data categorization";

      log.start(
        "Conformance test: mdoc nameSpaces unique naming per ISO 18013-5 §8.3.2.1.2 / §7.1",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_141 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          // -----------------------------------------------------------------
          // 1. Duplicate-key detection at the raw CBOR level.
          //    Default decode collapses duplicate map keys silently, so we
          //    rely on the `cbor` package's built-in `preventDuplicateKeys`
          //    option (throws on any duplicate map key anywhere in the
          //    decoded tree — including inside `nameSpaces`).
          //    RFC 8949 §3.1: CBOR maps should not contain duplicate keys.
          // -----------------------------------------------------------------
          let duplicateKeyError: Error | undefined;
          try {
            decode(raw, { preventDuplicateKeys: true });
          } catch (error) {
            duplicateKeyError =
              error instanceof Error ? error : new Error(String(error));
          }

          expect(
            duplicateKeyError,
            `Duplicate CBOR map keys detected in mdoc credential (RFC 8949 §3.1 / ISO 18013-5 §8.3.2.1.2): ${duplicateKeyError?.message ?? ""}`,
          ).toBeUndefined();

          // -----------------------------------------------------------------
          // 2. Standard decode to inspect the nameSpaces key set.
          // -----------------------------------------------------------------
          const decoded = decode(raw) as Record<string, unknown>;
          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          // ≥ 1 entry (overlaps with CI_140 by design — matches the
          // compliance-table wording for row CI_141 verbatim)
          const nsKeys = Object.keys(nameSpaces);

          expect(
            nsKeys.length,
            "nameSpaces must declare at least one nameSpace entry (ISO 18013-5 §8.3.2.1.2)",
          ).toBeGreaterThan(0);

          // 3. Each key is a non-empty text string. JS object keys are
          //    always strings, but the empty string `""` is a legal CBOR
          //    map key that carries no organisational meaning.
          for (const key of nsKeys) {
            expect(
              typeof key === "string" && key.length > 0,
              `nameSpace name "${key}" must be a non-empty text string (ISO 18013-5 §7.1)`,
            ).toBe(true);
          }

          // 4. Advisory only: ISO 18013-5 §7.1 recommends reverse-domain
          //    form (e.g. `org.iso.18013.5.1`, `eu.europa.ec.eudi.pid.1`).
          //    Logged as a warning to avoid false negatives on legacy issuers.
          for (const key of nsKeys) {
            const isReverseDomain = /^[a-z0-9]+(\.[a-z0-9_-]+)+$/i.test(key);
            if (!isReverseDomain) {
              log.debug(
                `  ⚠ nameSpace "${key}" does not match ISO 18013-5 §7.1 reverse-domain form`,
              );
            }
          }

          log.debug(
            `  ✓ ${nsKeys.length} unique nameSpace(s): ${nsKeys.join(", ")}`,
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_142 — Mdoc IssuerSignedItemBytes are CBOR Tag 24 byte strings
    //         (#6.24(bstr .cbor))
    // =======================================================================

    test("CI_142: Mdoc Credential Format | Within each nameSpace, one or more IssuerSignedItemBytes are correctly encoded as CBOR byte strings with Tag 24 (#6.24(bstr .cbor))", async () => {
      const log = baseLog.withTag("CI_142");
      const DESCRIPTION =
        "Within each nameSpace, one or more IssuerSignedItemBytes are correctly encoded as CBOR byte strings with Tag 24 (#6.24(bstr .cbor)), appearing as 24(<<...>>) in diagnostic notation";

      log.start(
        "Conformance test: mdoc IssuerSignedItemBytes Tag 24 encoding per RFC 8949 §3.4.5.1 / ISO 18013-5 §9.1.2.5 / §8.3.2.1.2.2",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_142 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          const decoded = decode(raw) as Record<string, unknown>;
          const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

          const nsKeys = Object.keys(nameSpaces);
          log.debug(`  nameSpaces keys: ${nsKeys.join(", ")}`);

          for (const [ns, items] of Object.entries(nameSpaces)) {
            // 1. Array of IssuerSignedItemBytes
            expect(
              Array.isArray(items),
              `nameSpaces["${ns}"] must be a CBOR array of IssuerSignedItemBytes`,
            ).toBe(true);

            // 2. "one or more"
            const arr = items as unknown[];
            expect(
              arr.length,
              `nameSpaces["${ns}"] must contain at least one IssuerSignedItemBytes`,
            ).toBeGreaterThan(0);

            // 3. Tag 24 byte-string wrapping valid CBOR — per element
            arr.forEach((item, idx) => {
              expect(
                item instanceof Tagged,
                `nameSpaces["${ns}"][${idx}] must be a CBOR Tagged item (RFC 8949 §3.4)`,
              ).toBe(true);

              const tagged = item as cbor.Tagged;

              expect(
                tagged.tag,
                `nameSpaces["${ns}"][${idx}] tag must be 24 (#6.24(bstr .cbor)) per RFC 8949 §3.4.5.1`,
              ).toBe(24);

              expect(
                tagged.value instanceof Uint8Array ||
                  Buffer.isBuffer(tagged.value),
                `Tag 24 content for nameSpaces["${ns}"][${idx}] must be a CBOR byte string (bstr)`,
              ).toBe(true);

              // The `.cbor` constraint: embedded bytes are themselves
              // well-formed CBOR.
              const inner = Buffer.isBuffer(tagged.value)
                ? tagged.value
                : Buffer.from(tagged.value as Uint8Array);

              let innerDecoded: unknown;
              let innerDecodeError: Error | undefined;
              try {
                innerDecoded = decode(inner);
              } catch (error) {
                innerDecodeError =
                  error instanceof Error ? error : new Error(String(error));
              }

              expect(
                innerDecodeError,
                `Tag 24 inner bytes for nameSpaces["${ns}"][${idx}] must decode as valid CBOR (RFC 8949 §3.4.5.1): ${innerDecodeError?.message ?? ""}`,
              ).toBeUndefined();

              expect(
                innerDecoded !== null && typeof innerDecoded === "object",
                `Tag 24 inner CBOR for nameSpaces["${ns}"][${idx}] must decode to a CBOR data item (the embedded IssuerSignedItem)`,
              ).toBe(true);

              log.debug(
                `  ✓ ${ns}[${idx}] = 24(<<…${inner.length} bytes…>>) — valid Tag 24 bstr .cbor`,
              );
            });
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_143 — Mdoc IssuerSignedItem required attributes
    //         (digestID, random, elementIdentifier, elementValue)
    // =======================================================================

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

              // Helpers — match the Map-or-plain-object pattern used by
              // CI_138 / CI_139 (cbor returns Map when keys are non-string).
              const has = (key: string): boolean =>
                item instanceof Map
                  ? item.has(key)
                  : key in (item as Record<string, unknown>);
              const get = (key: string): unknown =>
                item instanceof Map
                  ? item.get(key)
                  : (item as Record<string, unknown>)[key];

              // ---------------------------------------------------------
              // 1. digestID: CBOR unsigned integer (uint)
              //    ISO 18013-5 §9.1.2.5
              // ---------------------------------------------------------
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

              // ---------------------------------------------------------
              // 2. random: CBOR byte string (bstr)
              //    ISO 18013-5 §9.1.2.5
              //    Note: minimum-length (≥16) and per-item uniqueness are
              //    covered by CI_139; this test asserts the CBOR type only.
              // ---------------------------------------------------------
              expect(
                has("random"),
                `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "random" (ISO 18013-5 §9.1.2.5)`,
              ).toBe(true);

              const random = get("random");

              expect(
                Buffer.isBuffer(random) || random instanceof Uint8Array,
                `random in nameSpaces["${ns}"][${idx}] must be a CBOR byte string (bstr) per ISO 18013-5 §9.1.2.5`,
              ).toBe(true);

              // ---------------------------------------------------------
              // 3. elementIdentifier: CBOR text string (tstr), non-empty
              //    ISO 18013-5 §8.3.2.1.2.3
              // ---------------------------------------------------------
              expect(
                has("elementIdentifier"),
                `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "elementIdentifier" (ISO 18013-5 §8.3.2.1.2.3)`,
              ).toBe(true);

              const elementIdentifier = get("elementIdentifier");

              expect(
                typeof elementIdentifier === "string" &&
                  (elementIdentifier as string).length > 0,
                `elementIdentifier in nameSpaces["${ns}"][${idx}] must be a non-empty CBOR text string (tstr) per ISO 18013-5 §8.3.2.1.2.3`,
              ).toBe(true);

              // ---------------------------------------------------------
              // 4. elementValue: CDDL `any` — key presence only.
              //    ISO 18013-5 §8.3.2.1.2.3
              //    CBOR `null` is allowed; no type assertion.
              // ---------------------------------------------------------
              expect(
                has("elementValue"),
                `IssuerSignedItem in nameSpaces["${ns}"][${idx}] must contain attribute "elementValue" (ISO 18013-5 §8.3.2.1.2.3)`,
              ).toBe(true);

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

    // =======================================================================
    // CI_144 — Mdoc Element Identifiers Presence Validation
    // =======================================================================

    function validateMdocRawCredential(
      raw: Buffer,
      log: { debug: (msg: string) => void },
    ): void {
      const decoded = decode(raw) as Record<string, unknown>;
      const nameSpaces = decoded["nameSpaces"] as Record<string, unknown>;

      // Build flat index: elementsByNs[namespace][elementIdentifier] = elementValue
      const elementsByNs: Record<string, Record<string, unknown>> = {};

      for (const [ns, items] of Object.entries(nameSpaces)) {
        const nsRecord: Record<string, unknown> = {};
        elementsByNs[ns] = nsRecord;
        for (const tagged of items as cbor.Tagged[]) {
          const inner = Buffer.isBuffer(tagged.value)
            ? tagged.value
            : Buffer.from(tagged.value as Uint8Array);
          const item = decode(inner) as
            | Map<string, unknown>
            | Record<string, unknown>;

          const has = (key: string): boolean =>
            item instanceof Map
              ? item.has(key)
              : key in (item as Record<string, unknown>);
          const get = (key: string): unknown =>
            item instanceof Map
              ? item.get(key)
              : (item as Record<string, unknown>)[key];

          if (has("elementIdentifier") && has("elementValue")) {
            const id = get("elementIdentifier") as string;
            nsRecord[id] = get("elementValue");
          }
        }
      }

      const nsEudi = elementsByNs["eu.europa.ec.eudi.pid.1"] ?? {};
      const nsIt = elementsByNs["eu.europa.ec.eudi.pid.it.1"] ?? {};

      validateMdocNameSpaces(nsEudi, nsIt, log);
    }

    function validateMdocNameSpaces(
      nsEudi: Record<string, unknown>,
      nsIt: Record<string, unknown>,
      log: { debug: (msg: string) => void },
    ): void {
      // -----------------------------------------------------------------
      // eu.europa.ec.eudi.pid.1 — REQUIRED elements
      // -----------------------------------------------------------------

      // issuing_country — tstr, REQUIRED, ISO 3166-1 Alpha-2 (ISO 18013-5 §7.2)
      expect(
        "issuing_country" in nsEudi,
        'namespace "eu.europa.ec.eudi.pid.1" must contain REQUIRED element "issuing_country" (ISO 18013-5 §7.2)',
      ).toBe(true);

      expect(
        typeof nsEudi["issuing_country"],
        '"issuing_country" elementValue must be a tstr (CBOR text string) per ISO 18013-5 §7.2',
      ).toBe("string");

      expect(
        /^[A-Z]{2}$/.test(nsEudi["issuing_country"] as string),
        `"issuing_country" must be an ISO 3166-1 Alpha-2 country code (2 uppercase letters), got "${String(nsEudi["issuing_country"])}"`,
      ).toBe(true);

      log.debug(`  ✓ issuing_country="${String(nsEudi["issuing_country"])}"`);

      // issuing_authority — tstr, REQUIRED, Latin1b ≤150 chars (ISO 18013-5 §7.2)
      expect(
        "issuing_authority" in nsEudi,
        'namespace "eu.europa.ec.eudi.pid.1" must contain REQUIRED element "issuing_authority" (ISO 18013-5 §7.2)',
      ).toBe(true);

      const issuingAuthority = nsEudi["issuing_authority"] as string;

      expect(
        typeof issuingAuthority,
        '"issuing_authority" elementValue must be a tstr (CBOR text string) per ISO 18013-5 §7.2',
      ).toBe("string");

      expect(
        issuingAuthority.length <= 150,
        `"issuing_authority" must have a maximum length of 150 characters (ISO 18013-5 §7.2), got ${issuingAuthority.length}`,
      ).toBe(true);

      // Latin1b = ISO 8859-1 code points 0x20–0xFF
      expect(
        /^[\u0020-\u00FF]*$/.test(issuingAuthority),
        '"issuing_authority" must contain only Latin1b characters (ISO 8859-1 code points 0x20–0xFF, ISO 18013-5 §7.2)',
      ).toBe(true);

      log.debug(`  ✓ issuing_authority="${issuingAuthority}"`);

      // -----------------------------------------------------------------
      // eu.europa.ec.eudi.pid.1 — OPTIONAL elements
      // -----------------------------------------------------------------

      // issuance_date — tdate (CBOR tag 0) or full-date (CBOR tag 1004), OPTIONAL (ARF PID Rulebook v1.3 §2.6)
      const issuanceDateInNs = "issuance_date" in nsEudi;
      const issuanceDateIsValid =
        !issuanceDateInNs ||
        nsEudi["issuance_date"] instanceof Date ||
        (nsEudi["issuance_date"] instanceof Tagged &&
          (nsEudi["issuance_date"] as CborTagged).tag === 1004 &&
          typeof (nsEudi["issuance_date"] as CborTagged).value === "string");
      expect(
        issuanceDateIsValid,
        '"issuance_date" elementValue must be a tdate (CBOR tag 0) or full-date (CBOR tag 1004) per ARF PID Rulebook v1.3 §2.6',
      ).toBe(true);
      if (issuanceDateInNs) {
        log.debug(`  ✓ issuance_date present and valid type`);
      }

      // expiry_date — tdate or full-date, REQUIRED for PID (ARF PID Rulebook v1.3 §3)
      expect(
        "expiry_date" in nsEudi,
        'namespace "eu.europa.ec.eudi.pid.1" must contain REQUIRED (for PID) element "expiry_date" (ARF PID Rulebook v1.3 §3)',
      ).toBe(true);

      const expiryDate = nsEudi["expiry_date"];
      const expiryDateIsValid =
        expiryDate instanceof Date ||
        (expiryDate instanceof Tagged &&
          expiryDate.tag === 1004 &&
          typeof expiryDate.value === "string");

      expect(
        expiryDateIsValid,
        '"expiry_date" elementValue must be a tdate (CBOR tag 0) or full-date (CBOR tag 1004) per ARF PID Rulebook v1.3 §3',
      ).toBe(true);

      // ISO 8601-1 YYYY-MM-DD format check (applies to full-date; tdate is already a Date)
      const expiryDateIsFullDate =
        expiryDate instanceof Tagged && expiryDate.tag === 1004;
      const expiryDateFormatIsValid =
        !expiryDateIsFullDate ||
        /^\d{4}-\d{2}-\d{2}$/.test((expiryDate as CborTagged).value as string);
      expect(
        expiryDateFormatIsValid,
        `"expiry_date" full-date value must conform to ISO 8601-1 YYYY-MM-DD format, got "${String(expiryDateIsFullDate ? (expiryDate as CborTagged).value : "")}"`,
      ).toBe(true);

      log.debug(`  ✓ expiry_date present and valid type`);

      // -----------------------------------------------------------------
      // eu.europa.ec.eudi.pid.it.1 — REQUIRED elements (PID domestic extension)
      // -----------------------------------------------------------------

      // sub — uuid tstr, REQUIRED for PID (IT-Wallet domestic extension)
      expect(
        "sub" in nsIt,
        'namespace "eu.europa.ec.eudi.pid.it.1" must contain REQUIRED (for PID) element "sub" (IT-Wallet domestic extension)',
      ).toBe(true);

      const sub = nsIt["sub"] as string;

      expect(
        typeof sub,
        '"sub" elementValue must be a tstr (CBOR text string / UUID)',
      ).toBe("string");

      // UUID format: 8-4-4-4-12 hex groups
      expect(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
          sub,
        ),
        `"sub" must be a valid UUID string, got "${sub}"`,
      ).toBe(true);

      log.debug(`  ✓ sub="${sub}"`);

      // verification — CBOR map, REQUIRED for PID (IT-Wallet domestic extension)
      expect(
        "verification" in nsIt,
        'namespace "eu.europa.ec.eudi.pid.it.1" must contain REQUIRED (for PID) element "verification" (IT-Wallet domestic extension)',
      ).toBe(true);

      const verification = nsIt["verification"];

      expect(
        verification !== null && typeof verification === "object",
        '"verification" elementValue must be a CBOR map',
      ).toBe(true);

      const vHas = (key: string): boolean =>
        verification instanceof Map
          ? verification.has(key)
          : key in (verification as Record<string, unknown>);
      const vGet = (key: string): unknown =>
        verification instanceof Map
          ? verification.get(key)
          : (verification as Record<string, unknown>)[key];

      // trust_framework — tstr, REQUIRED within verification map
      expect(
        vHas("trust_framework"),
        '"verification" map must contain REQUIRED sub-field "trust_framework" (IT-Wallet domestic extension)',
      ).toBe(true);

      expect(
        typeof vGet("trust_framework") === "string" &&
          (vGet("trust_framework") as string).length > 0,
        '"verification.trust_framework" must be a non-empty tstr',
      ).toBe(true);

      // assurance_level — tstr, REQUIRED within verification map
      expect(
        vHas("assurance_level"),
        '"verification" map must contain REQUIRED sub-field "assurance_level" (IT-Wallet domestic extension)',
      ).toBe(true);

      expect(
        typeof vGet("assurance_level") === "string" &&
          (vGet("assurance_level") as string).length > 0,
        '"verification.assurance_level" must be a non-empty tstr',
      ).toBe(true);

      log.debug(
        `  ✓ verification map valid: trust_framework="${String(vGet("trust_framework"))}", assurance_level="${String(vGet("assurance_level"))}"`,
      );
    }

    test("CI_144: Mdoc Element Identifiers | All elementIdentifiers defined in the attribute table are properly included in the mdoc-CBOR Digital Credential within their respective nameSpaces", async () => {
      const log = baseLog.withTag("CI_144");
      const DESCRIPTION =
        "All elementIdentifiers in the elementIdentifiers attribute table are properly included in the Digital Credential encoded in mdoc-CBOR within their respective nameSpaces, unless otherwise specified";

      log.start(
        "Conformance test: mdoc element identifiers per IT-Wallet table_element_identifiers_mdoc / ISO 18013-5 §7.2 / ARF PID Rulebook v1.3",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_144 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          expect(
            () => validateMdocRawCredential(raw, log),
            "mdoc credential must include all required elementIdentifiers in expected nameSpaces",
          ).not.toThrow();
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_145 — issuerAuth is a properly formatted COSE Sign1 Document
    //         per RFC 9052 (protected header, unprotected header, payload,
    //         signature all correctly structured)
    // =======================================================================

    test("CI_145: Mdoc IssuerAuth COSE Sign1 | The issuerAuth successfully represents the Mobile Security Object as a properly formatted COSE Sign1 Document according to RFC 9052, containing the complete required data structure with: protected header, unprotected header, payload and signature components", async () => {
      const log = baseLog.withTag("CI_145");
      const DESCRIPTION =
        "The issuerAuth successfully represents the Mobile Security Object as a properly formatted COSE Sign1 Document according to RFC 9052, containing the complete required data structure with: protected header, unprotected header, payload and signature components";

      log.start(
        "Conformance test: issuerAuth COSE_Sign1 structure per RFC 9052 §4.2 / ISO 18013-5 §9.1.2.4",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_145 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          const decoded = decode(raw) as Record<string, unknown>;
          const issuerAuth = decoded["issuerAuth"] as unknown[];

          // -----------------------------------------------------------------
          // 1. COSE_Sign1 is a 4-element CBOR array
          //    [protected, unprotected, payload, signature] per RFC 9052 §4.2
          // -----------------------------------------------------------------
          expect(
            Array.isArray(issuerAuth),
            "issuerAuth must be a CBOR array encoding a COSE_Sign1 structure (RFC 9052 §4.2)",
          ).toBe(true);

          expect(
            issuerAuth.length,
            "COSE_Sign1 must be a 4-tuple: [protected, unprotected, payload, signature] (RFC 9052 §4.2)",
          ).toBe(4);

          const [protectedHeader, unprotectedHeader, payload, signature] =
            issuerAuth;

          // -----------------------------------------------------------------
          // 2. Protected header — bstr that decodes to a CBOR map
          //    (RFC 9052 §3, `empty_or_serialized_map`)
          //    Note: alg (label 1) presence and value are validated by CI_146.
          // -----------------------------------------------------------------
          expect(
            protectedHeader instanceof Uint8Array ||
              Buffer.isBuffer(protectedHeader),
            "COSE_Sign1[0] (protected header) must be a CBOR byte string (bstr) per RFC 9052 §3",
          ).toBe(true);

          const protectedHeaderBuf = Buffer.isBuffer(protectedHeader)
            ? protectedHeader
            : Buffer.from(protectedHeader as Uint8Array);

          const protectedHeaderMap = decode(protectedHeaderBuf) as
            | Map<number | string, unknown>
            | Record<number | string, unknown>;

          expect(
            typeof protectedHeaderMap === "object" &&
              protectedHeaderMap !== null,
            "COSE_Sign1[0] protected header byte string must decode to a CBOR map (RFC 9052 §3)",
          ).toBe(true);

          log.debug(`  ✓ protected header: bstr → CBOR map`);

          // -----------------------------------------------------------------
          // 3. Unprotected header — must be a CBOR map (RFC 9052 §3)
          //    May be empty; type is the key assertion.
          // -----------------------------------------------------------------
          expect(
            unprotectedHeader !== null && typeof unprotectedHeader === "object",
            "COSE_Sign1[1] (unprotected header) must be a CBOR map (RFC 9052 §3)",
          ).toBe(true);

          log.debug(`  ✓ unprotected header: CBOR map`);

          // -----------------------------------------------------------------
          // 4. Payload — non-null, non-empty bstr (RFC 9052 §4.2)
          //    ISO 18013-5 always carries the MSO as inline (not detached)
          //    payload, so nil is not valid here.
          // -----------------------------------------------------------------
          expect(
            payload !== null && payload !== undefined,
            "COSE_Sign1[2] (payload) must be present (not nil/detached) — the MSO is always carried inline in mdoc (RFC 9052 §4.2 / ISO 18013-5 §9.1.2.4)",
          ).toBe(true);

          expect(
            payload instanceof Uint8Array || Buffer.isBuffer(payload),
            "COSE_Sign1[2] (payload) must be a CBOR byte string (bstr) per RFC 9052 §4.2",
          ).toBe(true);

          const payloadBuf = Buffer.isBuffer(payload)
            ? payload
            : Buffer.from(payload as Uint8Array);

          expect(
            payloadBuf.length,
            "COSE_Sign1[2] (payload) byte string must be non-empty (RFC 9052 §4.2)",
          ).toBeGreaterThan(0);

          log.debug(`  ✓ payload: ${payloadBuf.length} bytes (non-empty bstr)`);

          // -----------------------------------------------------------------
          // 5. Signature — non-empty bstr (RFC 9052 §4.2)
          //    A zero-length signature is cryptographically invalid.
          // -----------------------------------------------------------------
          expect(
            signature instanceof Uint8Array || Buffer.isBuffer(signature),
            "COSE_Sign1[3] (signature) must be a CBOR byte string (bstr) per RFC 9052 §4.2",
          ).toBe(true);

          const sigBuf = Buffer.isBuffer(signature)
            ? signature
            : Buffer.from(signature as Uint8Array);

          expect(
            sigBuf.length,
            "COSE_Sign1[3] (signature) must be non-empty — a zero-length signature is cryptographically invalid (RFC 9052 §4.2)",
          ).toBeGreaterThan(0);

          log.debug(
            `  ✓ issuerAuth is a valid COSE_Sign1: payloadLen=${payloadBuf.length}, sigLen=${sigBuf.length}`,
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_146 — Protected Header alg Parameter (Label 1 int) CBOR Encoding
    // =======================================================================

    test(
      "CI_146: Mdoc Credential Format | The protected header successfully contains " +
        "the `alg` parameter (label 1, int) properly encoded as a CBOR integer per RFC 9053",
      async () => {
        const log = baseLog.withTag("CI_146");
        const DESCRIPTION =
          "The issuerAuth COSE_Sign1 protected header contains label 1 (alg) encoded as " +
          "a CBOR integer value identifying the algorithm used to verify the mdoc Digital " +
          "Credential's cryptographic signature (RFC 9053)";

        log.start(
          "Conformance test: issuerAuth protected header alg parameter per RFC 9052 §3.1 / RFC 9053",
        );

        // COSE alg header parameter label is integer 1 (RFC 9052 §3.1)
        const COSE_ALG_LABEL = 1;

        let testSuccess = false;
        try {
          const mdocCredentials = getMdocCredentials();

          if (mdocCredentials.length === 0) {
            log.debug("→ CI_146 skipped: no mdoc credentials found");
            testSuccess = true;
            return;
          }

          for (const { raw } of mdocCredentials) {
            const decoded = decode(raw) as Record<string, unknown>;

            const issuerAuth = decoded["issuerAuth"];

            expect(
              Array.isArray(issuerAuth) &&
                (issuerAuth as unknown[]).length >= 4,
              `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
            ).toBe(true);

            const protectedHeaderBytes = (issuerAuth as unknown[])[0];

            expect(
              Buffer.isBuffer(protectedHeaderBytes) ||
                protectedHeaderBytes instanceof Uint8Array,
              `issuerAuth[0] (protected header) must be a bstr (byte string) per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; got ${typeof protectedHeaderBytes}`,
            ).toBe(true);

            // Decode protected header byte string → CBOR map
            const protectedHeaderMap = decode(
              Buffer.isBuffer(protectedHeaderBytes)
                ? protectedHeaderBytes
                : Buffer.from(protectedHeaderBytes as Uint8Array),
            ) as
              | Map<number | string, unknown>
              | Record<number | string, unknown>;

            // ---------------------------------------------------------------
            // Label 1 (int) must be present as a CBOR integer key
            // (COSE alg parameter, RFC 9052 §3.1)
            // ---------------------------------------------------------------
            const hasAlg =
              protectedHeaderMap instanceof Map
                ? protectedHeaderMap.has(COSE_ALG_LABEL)
                : COSE_ALG_LABEL in
                  (protectedHeaderMap as Record<number | string, unknown>);

            expect(
              hasAlg,
              "Protected header must contain COSE label 1 (alg) as a CBOR integer key (RFC 9052 §3.1 / RFC 9053)",
            ).toBe(true);

            // ---------------------------------------------------------------
            // Value must be a CBOR integer (RFC 9053 algorithm identifiers)
            // ---------------------------------------------------------------
            const algValue =
              protectedHeaderMap instanceof Map
                ? protectedHeaderMap.get(COSE_ALG_LABEL)
                : (protectedHeaderMap as Record<number | string, unknown>)[
                    COSE_ALG_LABEL
                  ];

            expect(
              typeof algValue === "number" && Number.isInteger(algValue),
              "Protected header alg value (label 1) must be a CBOR integer per RFC 9053",
            ).toBe(true);

            log.debug(
              `  ✓ Protected header alg (label 1) = ${String(algValue)} ` +
                `(COSE algorithm integer per RFC 9053)`,
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_147 — Protected Header Required Signature Algorithm Value
    // =======================================================================

    test(
      "CI_147: Mdoc Credential Format | The protected header successfully contains " +
        "the required signature algorithm parameter (ESP256=-9, ESP384=-51, ESP512=-52 per IT-Wallet mdoc profile / RFC 9864)",
      async () => {
        const log = baseLog.withTag("CI_147");
        const DESCRIPTION =
          "The issuerAuth COSE_Sign1 protected header alg parameter (label 1) contains " +
          "a value corresponding to a required signature algorithm identifier per the IT-Wallet mdoc profile / RFC 9864 " +
          "(ESP256=-9, ESP384=-51, ESP512=-52)";

        log.start(
          "Conformance test: issuerAuth protected header alg value per IT-Wallet mdoc profile / RFC 9864 / ISO 18013-5 §9.1.2.4",
        );

        // COSE algorithm integers → algorithm names (RFC 9864 / IT-Wallet mdoc profile)
        const COSE_ALG_LABEL = 1;
        const REQUIRED_COSE_ALG_VALUES: ReadonlyMap<number, string> = new Map([
          [-52, "ESP512"],
          [-51, "ESP384"],
          [-9, "ESP256"],
        ]);

        let testSuccess = false;
        try {
          const mdocCredentials = getMdocCredentials();

          if (mdocCredentials.length === 0) {
            log.debug("→ CI_147 skipped: no mdoc credentials found");
            testSuccess = true;
            return;
          }

          for (const { raw } of mdocCredentials) {
            const decoded = decode(raw) as Record<string, unknown>;
            const issuerAuth = decoded["issuerAuth"];

            expect(
              Array.isArray(issuerAuth) &&
                (issuerAuth as unknown[]).length >= 4,
              `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
            ).toBe(true);

            const protectedHeaderBytes = (issuerAuth as unknown[])[0];

            expect(
              Buffer.isBuffer(protectedHeaderBytes) ||
                protectedHeaderBytes instanceof Uint8Array,
              `issuerAuth[0] (protected header) must be a bstr (byte string) per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; got ${typeof protectedHeaderBytes}`,
            ).toBe(true);

            const protectedHeaderMap = decode(
              Buffer.isBuffer(protectedHeaderBytes)
                ? protectedHeaderBytes
                : Buffer.from(protectedHeaderBytes as Uint8Array),
            ) as
              | Map<number | string, unknown>
              | Record<number | string, unknown>;

            const algValue =
              protectedHeaderMap instanceof Map
                ? protectedHeaderMap.get(COSE_ALG_LABEL)
                : (protectedHeaderMap as Record<number | string, unknown>)[
                    COSE_ALG_LABEL
                  ];

            const allowedAlgList = [...REQUIRED_COSE_ALG_VALUES.entries()].map(
              ([k, v]) => `${v}=${k}`,
            );

            expect(
              REQUIRED_COSE_ALG_VALUES.has(algValue as number),
              `Protected header alg (label 1) must be one of the required COSE algorithm identifiers per IT-Wallet mdoc profile / RFC 9864 (${allowedAlgList.join(", ")}), got ${String(algValue)}`,
            ).toBe(true);

            const algName =
              REQUIRED_COSE_ALG_VALUES.get(algValue as number) ?? "unknown";

            log.debug(
              `  ✓ Protected header alg (label 1) = ${String(algValue)} (${algName}) — ` +
                `required COSE signature algorithm per IT-Wallet mdoc profile / RFC 9864`,
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_147a — Protected Header Contains Only the Signature Algorithm
    // =======================================================================

    test(
      "CI_147a: Mdoc Credential Format | The protected header does not contain " +
        "elements different from the signature algorithm (RFC 9052 §3.1 / ISO 18013-5 §9.1.2.4)",
      async () => {
        const log = baseLog.withTag("CI_147a");
        const DESCRIPTION =
          "The issuerAuth COSE_Sign1 protected header contains only the alg parameter " +
          "(label 1) and no other COSE header parameters. ISO 18013-5 §9.1.2.4 restricts " +
          "the protected header to the algorithm identifier exclusively (RFC 9052 §3.1)";

        log.start(
          "Conformance test: issuerAuth protected header contains only alg per RFC 9052 §3.1 / ISO 18013-5 §9.1.2.4",
        );

        // COSE alg header parameter label is integer 1 (RFC 9052 §3.1)
        const COSE_ALG_LABEL = 1;

        let testSuccess = false;
        try {
          const mdocCredentials = getMdocCredentials();

          if (mdocCredentials.length === 0) {
            log.debug("→ CI_147a skipped: no mdoc credentials found");
            testSuccess = true;
            return;
          }

          for (const { raw } of mdocCredentials) {
            const decoded = decode(raw) as Record<string, unknown>;

            const issuerAuth = decoded["issuerAuth"];

            expect(
              Array.isArray(issuerAuth) &&
                (issuerAuth as unknown[]).length >= 4,
              `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
            ).toBe(true);

            const protectedHeaderBytes = (issuerAuth as unknown[])[0];

            expect(
              Buffer.isBuffer(protectedHeaderBytes) ||
                protectedHeaderBytes instanceof Uint8Array,
              `issuerAuth[0] (protected header) must be a bstr (byte string) per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; got ${typeof protectedHeaderBytes}`,
            ).toBe(true);

            // Decode protected header byte string → CBOR map (same path as CI_146/CI_147)
            const protectedHeaderMap = decode(
              Buffer.isBuffer(protectedHeaderBytes)
                ? protectedHeaderBytes
                : Buffer.from(protectedHeaderBytes as Uint8Array),
            ) as
              | Map<number | string, unknown>
              | Record<number | string, unknown>;

            // Collect all keys, normalising Object.keys() strings to numbers
            // so they can be compared to the integer COSE label.
            const allKeys: (number | string)[] =
              protectedHeaderMap instanceof Map
                ? [...protectedHeaderMap.keys()]
                : Object.keys(protectedHeaderMap).map(Number);

            const unexpectedKeys = allKeys.filter((k) => k !== COSE_ALG_LABEL);
            const hasOnlyAlg = unexpectedKeys.length === 0;

            expect(
              hasOnlyAlg,
              `Protected header must contain only the alg parameter (label 1) per RFC 9052 §3.1 / ISO 18013-5 §9.1.2.4. Unexpected labels found: [${unexpectedKeys.join(", ")}]`,
            ).toBe(true);

            log.debug(
              `  ✓ Protected header contains only alg (label 1) — no extra parameters`,
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_148 — Unprotected Header Optional Parameters Type Validation
    //         (label 4: kid tstr, label 33: x5chain array)
    // =======================================================================

    test(
      "CI_148: Mdoc IssuerAuth Unprotected Header | Unless otherwise specified, " +
        "the unprotected header contains the optional parameters with correct CBOR types: " +
        "label 4 (kid, tstr) identifying the Issuer JWK for OpenID Federation, " +
        "and label 33 (x5chain, array) carrying the X.509 certificate chain for X.509-based authentication",
      async () => {
        const log = baseLog.withTag("CI_148");
        const DESCRIPTION =
          "The issuerAuth COSE_Sign1 unprotected header optional parameters have the correct CBOR types: " +
          "label 4 (kid) must be a tstr (text string) per the Infrastructure of Trust specification when present, " +
          "and label 33 (x5chain) must be an array of DER-encoded X.509 certificates per RFC 9360 when present";

        log.start(
          "Conformance test: issuerAuth unprotected header parameter types (label 4 tstr, label 33 array)",
        );

        // kid: unique identifier of the Issuer JWK (Infrastructure of Trust)
        const KID_LABEL = 4;
        // x5chain: X.509 certificate chain (RFC 9360)
        const X5CHAIN_LABEL = 33;

        let testSuccess = false;
        try {
          const mdocCredentials = getMdocCredentials();

          if (mdocCredentials.length === 0) {
            log.debug("→ CI_148 skipped: no mdoc credentials found");
            testSuccess = true;
            return;
          }

          for (const { raw } of mdocCredentials) {
            const decoded = decode(raw) as Record<string, unknown>;
            const issuerAuth = decoded["issuerAuth"];

            expect(
              Array.isArray(issuerAuth) &&
                (issuerAuth as unknown[]).length >= 4,
              `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
            ).toBe(true);

            // issuerAuth[1] is the unprotected header — already decoded as a
            // CBOR map by the cbor library; no additional Buffer.from/decode needed.
            const unprotectedHeader = (issuerAuth as unknown[])[1] as
              | Map<number, unknown>
              | Record<number | string, unknown>;

            const uhHas = (label: number): boolean =>
              unprotectedHeader instanceof Map
                ? unprotectedHeader.has(label)
                : label in
                  (unprotectedHeader as Record<number | string, unknown>);

            const uhGet = (label: number): unknown =>
              unprotectedHeader instanceof Map
                ? unprotectedHeader.get(label)
                : (unprotectedHeader as Record<number | string, unknown>)[
                    label
                  ];

            const kidPresent = uhHas(KID_LABEL);
            const x5chainPresent = uhHas(X5CHAIN_LABEL);
            const kidValue = uhGet(KID_LABEL);
            const x5chainValue = uhGet(X5CHAIN_LABEL);

            // -----------------------------------------------------------------
            // Label 4 (kid) — if present, must be a tstr (text string).
            // Carries the unique identifier of the Issuer JWK when the Issuer
            // of mdoc uses OpenID Federation (Infrastructure of Trust spec).
            // -----------------------------------------------------------------
            const kidIsValidType = !kidPresent || typeof kidValue === "string";

            expect(
              kidIsValidType,
              "Unprotected header label 4 (kid), when present, must be a tstr (text string) per the Infrastructure of Trust specification",
            ).toBe(true);

            log.debug(
              kidPresent
                ? `  ✓ label 4 (kid) = "${String(kidValue)}" (tstr)`
                : `  · label 4 (kid) not present — OpenID Federation not in use`,
            );

            // -----------------------------------------------------------------
            // Label 33 (x5chain) — if present, must be a bare bstr (single
            // certificate) or an array of DER-encoded X.509 certificates
            // (RFC 9360 §2). Required for X.509 certificate-based auth.
            // -----------------------------------------------------------------
            const x5chainIsBstr =
              !x5chainPresent ||
              Buffer.isBuffer(x5chainValue) ||
              x5chainValue instanceof Uint8Array;
            const x5chainIsArrayForm =
              !x5chainPresent || Array.isArray(x5chainValue);
            const x5chainValidEncoding = x5chainIsBstr || x5chainIsArrayForm;

            expect(
              x5chainValidEncoding,
              "Unprotected header label 33 (x5chain), when present, must be a bstr (single cert) or an array of bstr per RFC 9360 §2",
            ).toBe(true);

            const x5chainIsNonEmpty =
              !x5chainPresent ||
              (Array.isArray(x5chainValue)
                ? (x5chainValue as unknown[]).length > 0
                : Buffer.isBuffer(x5chainValue) ||
                  x5chainValue instanceof Uint8Array);

            expect(
              x5chainIsNonEmpty,
              "Unprotected header label 33 (x5chain), when present, must contain at least one certificate (RFC 9360 §2)",
            ).toBe(true);

            log.debug(
              x5chainPresent
                ? Array.isArray(x5chainValue)
                  ? `  ✓ label 33 (x5chain) = array[${(x5chainValue as unknown[]).length}] (X.509 certificate chain)`
                  : `  ✓ label 33 (x5chain) = bstr[${(x5chainValue as Uint8Array).byteLength}] (single X.509 certificate)`
                : `  · label 33 (x5chain) not present — X.509-based authentication not in use`,
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_148a — x5chain is correctly included in the unprotected header
    // =======================================================================

    test(
      "CI_148a: Mdoc IssuerAuth Unprotected Header | The x5chain is correctly " +
        "included in the unprotected header (label 33) per RFC 9360 and ISO 18013-5 §9.1.2.4",
      async () => {
        const log = baseLog.withTag("CI_148a");
        const DESCRIPTION =
          "The issuerAuth COSE_Sign1 unprotected header contains the x5chain " +
          "parameter (label 33) with at least one DER-encoded X.509 certificate. " +
          "Each element must be parseable as a valid X.509 certificate (RFC 9360, " +
          "ISO 18013-5 §9.1.2.4)";

        log.start(
          "Conformance test: x5chain present and valid in issuerAuth unprotected header (RFC 9360 / ISO 18013-5 §9.1.2.4)",
        );

        // COSE x5chain header label per RFC 9360
        const X5CHAIN_LABEL = 33;

        let testSuccess = false;
        try {
          const mdocCredentials = getMdocCredentials();

          if (mdocCredentials.length === 0) {
            log.debug("→ CI_148a skipped: no mdoc credentials found");
            testSuccess = true;
            return;
          }

          for (const { raw } of mdocCredentials) {
            const decoded = decode(raw) as Record<string, unknown>;
            const issuerAuth = decoded["issuerAuth"];

            expect(
              Array.isArray(issuerAuth) &&
                (issuerAuth as unknown[]).length >= 4,
              `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
            ).toBe(true);

            const unprotectedHeader = (issuerAuth as unknown[])[1] as
              | Map<number, unknown>
              | Record<number | string, unknown>;

            // Helper accessors (same pattern as CI_148)
            const uhHas = (label: number): boolean =>
              unprotectedHeader instanceof Map
                ? unprotectedHeader.has(label)
                : label in
                  (unprotectedHeader as Record<number | string, unknown>);

            const uhGet = (label: number): unknown =>
              unprotectedHeader instanceof Map
                ? unprotectedHeader.get(label)
                : (unprotectedHeader as Record<number | string, unknown>)[
                    label
                  ];

            // -----------------------------------------------------------------
            // Assertion 1 — x5chain MUST be present (required for X.509 issuance)
            // ISO 18013-5 §9.1.2.4 / RFC 9360
            // -----------------------------------------------------------------
            expect(
              uhHas(X5CHAIN_LABEL),
              "Unprotected header MUST contain x5chain (label 33) per RFC 9360 / ISO 18013-5 §9.1.2.4",
            ).toBe(true);

            const x5chainValue = uhGet(X5CHAIN_LABEL);

            // -----------------------------------------------------------------
            // Assertion 2 — value is a bstr or array of bstr (RFC 9360 §2)
            //   Single cert: Buffer | Uint8Array
            //   Chain:       Array<Buffer | Uint8Array>
            // -----------------------------------------------------------------
            const isSingleCert =
              Buffer.isBuffer(x5chainValue) ||
              x5chainValue instanceof Uint8Array;
            const isArray = Array.isArray(x5chainValue);

            expect(
              isSingleCert || isArray,
              "x5chain (label 33) must be a bstr (single certificate) or an array of bstr values per RFC 9360 §2",
            ).toBe(true);

            // Normalise to array for uniform iteration
            const certList: unknown[] = isSingleCert
              ? [x5chainValue]
              : (x5chainValue as unknown[]);

            expect(
              certList.length > 0,
              "x5chain must contain at least one DER-encoded X.509 certificate (RFC 9360 §2)",
            ).toBe(true);

            // -----------------------------------------------------------------
            // Assertion 3 — each element must be a parseable DER-encoded X.509
            //               certificate (@peculiar/x509 / RFC 9360 §2)
            // -----------------------------------------------------------------
            for (let i = 0; i < certList.length; i++) {
              const certBytes = certList[i];

              expect(
                Buffer.isBuffer(certBytes) || certBytes instanceof Uint8Array,
                `x5chain[${i}] must be a bstr (DER bytes) per RFC 9360 §2`,
              ).toBe(true);

              const derBuf = Buffer.isBuffer(certBytes)
                ? certBytes
                : Buffer.from(certBytes as Uint8Array);

              const ab = derBuf.buffer.slice(
                derBuf.byteOffset,
                derBuf.byteOffset + derBuf.byteLength,
              ) as ArrayBuffer;

              let cert: undefined | X509Certificate;
              try {
                cert = new X509Certificate(ab);
              } catch {
                // will fail the expect below
              }

              expect(
                cert,
                `x5chain[${i}] must be parseable as a valid DER-encoded X.509 certificate (RFC 9360 §2)`,
              ).toBeDefined();

              log.debug(
                `  ✓ x5chain[${i}] is a valid X.509 cert — subject: ${cert?.subject ?? "unknown"}`,
              );
            }

            log.debug(
              `  ✓ unprotected header x5chain (label 33) contains ${certList.length} valid certificate(s)`,
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_149 — MSO CBOR Tag 24 bstr Encoding + content-type Header Exclusion
    // =======================================================================

    test(
      "CI_149: Mdoc IssuerAuth Payload | The payload successfully contains the " +
        "MobileSecurityObject properly encoded as a byte string (bstr) using CBOR " +
        "Tag 24, with the content-type COSE Sign header parameter correctly " +
        "excluded from the structure",
      async () => {
        const log = baseLog.withTag("CI_149");
        const DESCRIPTION =
          "The payload successfully contains the MobileSecurityObject properly " +
          "encoded as a byte string (bstr) using CBOR Tag 24, with the " +
          "content-type COSE Sign header parameter correctly excluded from the structure";

        log.start(
          "Conformance test: MSO CBOR Tag 24 bstr encoding and content-type exclusion " +
            "per ISO 18013-5 §9.1.2.4 / RFC 8949 §3.4 / RFC 9052 §3.1",
        );

        // COSE content-type header parameter label (RFC 9052 §3.1 Table 2)
        const CONTENT_TYPE_LABEL = 3;

        let testSuccess = false;
        try {
          const mdocCredentials = getMdocCredentials();

          if (mdocCredentials.length === 0) {
            log.debug("→ CI_149 skipped: no mdoc credentials found");
            testSuccess = true;
            return;
          }

          for (const { raw } of mdocCredentials) {
            const decoded = decode(raw) as Record<string, unknown>;
            const issuerAuth = decoded["issuerAuth"];

            expect(
              Array.isArray(issuerAuth) &&
                (issuerAuth as unknown[]).length >= 4,
              `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
            ).toBe(true);

            const [protectedHeaderBytes, unprotectedHeader, payload] =
              issuerAuth as unknown[];

            // ---------------------------------------------------------------
            // 1. Payload is a CBOR byte string (bstr)
            //    RFC 9052 §4.2 / ISO 18013-5 §9.1.2.4
            // ---------------------------------------------------------------
            expect(
              payload instanceof Uint8Array || Buffer.isBuffer(payload),
              "COSE_Sign1[2] (payload) must be a CBOR byte string (bstr) per RFC 9052 §4.2 / ISO 18013-5 §9.1.2.4",
            ).toBe(true);

            const payloadBuf = Buffer.isBuffer(payload)
              ? payload
              : Buffer.from(payload as Uint8Array);

            // ---------------------------------------------------------------
            // 2. Payload bstr decodes to CBOR Tag 24 wrapping the MSO bstr.
            //    ISO 18013-5 §9.1.2.4:
            //      MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
            //    RFC 8949 §3.4 / §3.4.5.1: Tag 24 = embedded CBOR byte string.
            // ---------------------------------------------------------------
            const payloadTagged = decode(payloadBuf) as cbor.Tagged;

            expect(
              payloadTagged instanceof Tagged,
              "issuerAuth payload bstr must decode to a CBOR Tagged item (ISO 18013-5 §9.1.2.4 / RFC 8949 §3.4)",
            ).toBe(true);

            expect(
              payloadTagged.tag,
              "issuerAuth payload must use CBOR Tag 24 (MobileSecurityObjectBytes = #6.24(bstr .cbor MSO)) per ISO 18013-5 §9.1.2.4 / RFC 8949 §3.4.5.1",
            ).toBe(24);

            expect(
              payloadTagged.value instanceof Uint8Array ||
                Buffer.isBuffer(payloadTagged.value),
              "CBOR Tag 24 content must be a byte string (bstr) carrying the serialised MSO per ISO 18013-5 §9.1.2.4",
            ).toBe(true);

            const msoBytes = Buffer.isBuffer(payloadTagged.value)
              ? payloadTagged.value
              : Buffer.from(payloadTagged.value as Uint8Array);

            const mso = decode(msoBytes) as
              | Map<string, unknown>
              | Record<string, unknown>;

            expect(
              mso !== null && typeof mso === "object",
              "CBOR Tag 24 inner bytes must decode to a valid MobileSecurityObject map per ISO 18013-5 §9.1.2.4",
            ).toBe(true);

            log.debug(
              `  ✓ Payload: bstr(${payloadBuf.length}B) → Tag 24 → MSO map(${msoBytes.length}B)`,
            );

            // ---------------------------------------------------------------
            // 3a. Protected header must NOT contain content-type (label 3).
            //     ISO 18013-5 §9.1.2.4 restricts the COSE_Sign1 protected
            //     header to the alg parameter; the MSO type is statically
            //     defined by the CDDL grammar, making content-type redundant
            //     and non-conformant.
            //     RFC 9052 §3.1 Table 2: label 3 = content-type.
            // ---------------------------------------------------------------
            const protectedHeaderMap = decode(
              Buffer.isBuffer(protectedHeaderBytes)
                ? protectedHeaderBytes
                : Buffer.from(protectedHeaderBytes as Uint8Array),
            ) as
              | Map<number | string, unknown>
              | Record<number | string, unknown>;

            const protectedHasContentType =
              protectedHeaderMap instanceof Map
                ? protectedHeaderMap.has(CONTENT_TYPE_LABEL)
                : CONTENT_TYPE_LABEL in
                  (protectedHeaderMap as Record<number | string, unknown>);

            expect(
              !protectedHasContentType,
              "Protected header must not contain the content-type parameter (COSE label 3) per ISO 18013-5 §9.1.2.4 / RFC 9052 §3.1",
            ).toBe(true);

            // ---------------------------------------------------------------
            // 3b. Unprotected header must NOT contain content-type (label 3).
            //     Same rationale as 3a; the unprotected header is already
            //     decoded as a CBOR map by the cbor library.
            // ---------------------------------------------------------------
            const unprotectedHeaderMap = unprotectedHeader as
              | Map<number, unknown>
              | Record<number | string, unknown>;

            const unprotectedHasContentType =
              unprotectedHeaderMap instanceof Map
                ? unprotectedHeaderMap.has(CONTENT_TYPE_LABEL)
                : CONTENT_TYPE_LABEL in
                  (unprotectedHeaderMap as Record<number | string, unknown>);

            expect(
              !unprotectedHasContentType,
              "Unprotected header must not contain the content-type parameter (COSE label 3) per ISO 18013-5 §9.1.2.4 / RFC 9052 §3.1",
            ).toBe(true);

            log.debug(
              `  ✓ content-type (label 3) correctly excluded from both protected and unprotected headers`,
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_150 — MobileSecurityObject Required Attributes
    // =======================================================================

    test("CI_150: Mdoc IssuerAuth MSO | The MobileSecurityObject successfully contains all required attributes as specified in the compliance table (ISO 18013-5 §9.1.2.4)", async () => {
      const log = baseLog.withTag("CI_150");
      const DESCRIPTION =
        'The MobileSecurityObject successfully contains all required attributes as specified in the compliance table: version ("1.0"), digestAlgorithm (SHA-256/384/512), valueDigests, deviceKeyInfo with deviceKey, docType, and validityInfo with signed/validFrom/validUntil (ISO 18013-5 §9.1.2.4)';

      log.start(
        "Conformance test: MSO required attributes per ISO 18013-5 §9.1.2.4",
      );

      let testSuccess = false;
      try {
        const mdocCredentials = getMdocCredentials();

        if (mdocCredentials.length === 0) {
          log.debug("→ CI_150 skipped: no mdoc credentials found");
          testSuccess = true;
          return;
        }

        for (const { raw } of mdocCredentials) {
          const decoded = decode(raw) as Record<string, unknown>;
          const issuerAuth = decoded["issuerAuth"];

          expect(
            Array.isArray(issuerAuth) && (issuerAuth as unknown[]).length >= 4,
            `issuerAuth must be a COSE_Sign1 4-tuple [protected, unprotected, payload, signature] per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; found ${Array.isArray(issuerAuth) ? (issuerAuth as unknown[]).length : typeof issuerAuth} element(s)`,
          ).toBe(true);

          const payloadBytes = (issuerAuth as unknown[])[2];

          expect(
            Buffer.isBuffer(payloadBytes) || payloadBytes instanceof Uint8Array,
            `issuerAuth[2] (payload) must be a bstr (byte string) per RFC 9052 §4.2 / ISO 18013-5 §9.1.3; got ${typeof payloadBytes}`,
          ).toBe(true);

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

          const msoHas = (key: string): boolean =>
            mso instanceof Map ? mso.has(key) : key in mso;
          const msoGet = (key: string): unknown =>
            mso instanceof Map
              ? mso.get(key)
              : (mso as Record<string, unknown>)[key];

          // 1. version — present and equals "1.0"
          expect(
            msoHas("version"),
            "MSO must contain mandatory field version (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          expect(
            msoGet("version"),
            'MSO version must be "1.0" (ISO 18013-5 §9.1.2.4)',
          ).toBe("1.0");
          log.debug(`  ✓ version="${String(msoGet("version"))}"`);

          // 2. digestAlgorithm — present and one of the spec-allowed values
          const ALLOWED_DIGEST_ALGORITHMS = [
            "SHA-256",
            "SHA-384",
            "SHA-512",
          ] as const;
          expect(
            msoHas("digestAlgorithm"),
            "MSO must contain mandatory field digestAlgorithm (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          const digestAlgorithm = msoGet("digestAlgorithm") as string;
          expect(
            ALLOWED_DIGEST_ALGORITHMS.includes(
              digestAlgorithm as (typeof ALLOWED_DIGEST_ALGORITHMS)[number],
            ),
            `MSO digestAlgorithm must be one of ${ALLOWED_DIGEST_ALGORITHMS.join(", ")}, got "${digestAlgorithm}" (ISO 18013-5 §9.1.2.4)`,
          ).toBe(true);
          log.debug(`  ✓ digestAlgorithm="${digestAlgorithm}"`);

          // 3. valueDigests — present and is a map
          expect(
            msoHas("valueDigests"),
            "MSO must contain mandatory field valueDigests (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          const valueDigests = msoGet("valueDigests");
          expect(
            valueDigests !== null && typeof valueDigests === "object",
            "MSO valueDigests must be a map (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          log.debug("  ✓ valueDigests present and is a map");

          // 4. deviceKeyInfo — present, is a map, and contains deviceKey
          expect(
            msoHas("deviceKeyInfo"),
            "MSO must contain mandatory field deviceKeyInfo (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          const deviceKeyInfo = msoGet("deviceKeyInfo");
          expect(
            deviceKeyInfo !== null && typeof deviceKeyInfo === "object",
            "MSO deviceKeyInfo must be a map (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          const deviceKeyInfoHas = (key: string): boolean =>
            deviceKeyInfo instanceof Map
              ? deviceKeyInfo.has(key)
              : key in (deviceKeyInfo as Record<string, unknown>);
          expect(
            deviceKeyInfoHas("deviceKey"),
            "MSO deviceKeyInfo must contain deviceKey (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          log.debug("  ✓ deviceKeyInfo.deviceKey present");

          // 5. docType — present
          expect(
            msoHas("docType"),
            "MSO must contain mandatory field docType (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          log.debug(`  ✓ docType="${String(msoGet("docType"))}"`);

          // 6. validityInfo — present, is a map, and has signed/validFrom/validUntil
          expect(
            msoHas("validityInfo"),
            "MSO must contain mandatory field validityInfo (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          const validityInfo = msoGet("validityInfo");
          expect(
            validityInfo !== null && typeof validityInfo === "object",
            "MSO validityInfo must be a map (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          const validityInfoHas = (key: string): boolean =>
            validityInfo instanceof Map
              ? validityInfo.has(key)
              : key in (validityInfo as Record<string, unknown>);
          const validityInfoGet = (key: string): unknown =>
            validityInfo instanceof Map
              ? validityInfo.get(key)
              : (validityInfo as Record<string, unknown>)[key];
          expect(
            validityInfoHas("signed"),
            "MSO validityInfo must contain signed (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          expect(
            validityInfoHas("validFrom"),
            "MSO validityInfo must contain validFrom (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          expect(
            validityInfoHas("validUntil"),
            "MSO validityInfo must contain validUntil (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          log.debug(
            "  ✓ validityInfo: signed, validFrom, validUntil all present",
          );

          // 7. validFrom ≤ validUntil ordering (tdate = CBOR tag 0 → JS Date)
          const validFrom = validityInfoGet("validFrom") as Date;
          const validUntil = validityInfoGet("validUntil") as Date;
          expect(
            validFrom instanceof Date && validUntil instanceof Date,
            "MSO validityInfo.validFrom and validUntil must be tdate (ISO 18013-5 §9.1.2.4)",
          ).toBe(true);
          expect(
            validFrom.getTime() <= validUntil.getTime(),
            `MSO validityInfo.validFrom (${validFrom.toISOString()}) must be ≤ validUntil (${validUntil.toISOString()}) (ISO 18013-5 §9.1.2.4)`,
          ).toBe(true);
          log.debug(
            `  ✓ validFrom(${validFrom.toISOString()}) ≤ validUntil(${validUntil.toISOString()})`,
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
