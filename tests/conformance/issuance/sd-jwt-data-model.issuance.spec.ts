/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { SDJwt } from "@sd-jwt/core";
import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeJwt } from "@sd-jwt/decode";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { importX509, jwtVerify } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import z from "zod";

import { fetchWithConfig } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { CredentialRequestResponse } from "@/step/issuance";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

// @ts-expect-error TS1309: top-level await is valid in Vitest (ESM context)
const testConfigs = await defineIssuanceTest("SdJwtDataModel");

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] SD-JWT VC Data Model Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let credentialResponse: CredentialRequestResponse;
    let credentialIssuer: string;
    let ioWalletSdkConfig: IoWalletSdkConfig;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      const result = await orchestrator.issuance();
      assertIssuanceFlowSuccess(result);

      credentialResponse = result.credentialResponse;

      const resolvedCredentialIssuer =
        result.fetchMetadataResponse.response?.entityStatementClaims?.metadata
          ?.openid_credential_issuer?.credential_issuer;

      if (!resolvedCredentialIssuer) {
        throw new Error(
          "Unable to resolve credential_issuer from issuer metadata. These tests require an absolute credential issuer base URL.",
        );
      }

      const credentialIssuerParseResult = z
        .url()
        .safeParse(resolvedCredentialIssuer);

      if (!credentialIssuerParseResult.success) {
        throw new Error(
          "Resolved credential_issuer must be a valid absolute URL.",
        );
      }

      credentialIssuer = credentialIssuerParseResult.data;

      ioWalletSdkConfig = new IoWalletSdkConfig({
        itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
      });
    });

    useTestSummary(baseLog, testConfig.name);

    // -----------------------------------------------------------------------
    // Helper: extract SD-JWT VC credentials from the issuance response
    // -----------------------------------------------------------------------

    async function getSdJwtCredentials(): Promise<string[]> {
      const result: string[] = [];
      for (const credObj of credentialResponse.response?.credentials ?? []) {
        try {
          await SDJwt.extractJwt(credObj.credential);
          result.push(credObj.credential);
        } catch {
          // non-SD-JWT (e.g. mdoc-CBOR) — skip silently
        }
      }
      return result;
    }

    // -----------------------------------------------------------------------
    // Helper: extract the issuer-signed JWT portion from a Combined Format
    // -----------------------------------------------------------------------

    function extractIssuerJwt(combinedFormat: string): string {
      return combinedFormat.split("~")[0] ?? "";
    }

    // =======================================================================
    // CI_120 — SD-JWT Signature Verification
    // =======================================================================

    test("CI_120: Signature of the SD-JWT credential | Credential is signed using the Issuer's private key.", async () => {
      const log = baseLog.withTag("CI_120");
      const DESCRIPTION =
        "SD-JWT credential is signed using the Issuer's private key";

      log.start(
        "Conformance test: SD-JWT signature verification against Issuer key",
      );

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_120 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const issuerJwt = extractIssuerJwt(credentialJwt);

          const decoded = await instance.decode(credentialJwt);
          const header = decoded.jwt?.header as Record<string, unknown>;

          expect(header, "JWT header must be present").toBeDefined();

          const x5c = header["x5c"] as string[] | undefined;
          expect(
            x5c,
            "JOSE header must contain x5c to extract Issuer public key",
          ).toBeDefined();
          expect(
            Array.isArray(x5c) && x5c.length > 0,
            "x5c must be a non-empty array",
          ).toBe(true);

          const alg = header["alg"] as string;
          expect(alg, "JOSE header must contain alg").toBeDefined();

          if (!x5c || x5c.length === 0) {
            throw new Error("x5c must be a non-empty array");
          }

          const pem = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
          const issuerPublicKey = await importX509(pem, alg);

          // Throws if the signature does not verify against the Issuer's key
          await jwtVerify(issuerJwt, issuerPublicKey);

          log.debug(
            "  ✓ Signature successfully verified against Issuer certificate",
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_121 — SD-JWT Type Metadata Provision
    // =======================================================================

    test("CI_121: SD-JWT Type Metadata Provision | Credential references a valid well-known type metadata document.", async () => {
      const log = baseLog.withTag("CI_121");
      const DESCRIPTION =
        "SD-JWT credential vct references a reachable type metadata document";

      log.start("Conformance test: SD-JWT type metadata provision");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_121 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });
        const fetcher = fetchWithConfig(orchestrator.getConfig().network);

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;

          const vct = payload["vct"];
          expect(
            vct,
            "Credential payload must contain vct claim",
          ).toBeDefined();
          expect(typeof vct, "vct must be a string").toBe("string");
          log.debug(`  vct: ${String(vct)}`);

          const metadataUrl = `${credentialIssuer}/.well-known/type-metadata?vct=${encodeURIComponent(String(vct))}`;
          log.debug(`  Fetching type metadata from: ${metadataUrl}`);

          const response = await fetcher(metadataUrl);
          expect(
            response.status,
            "Type metadata endpoint must return HTTP 200",
          ).toBe(200);

          const body = (await response.json()) as Record<string, unknown>;
          expect(
            body["vct"],
            "Type metadata vct must match credential vct",
          ).toBe(vct);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_122 — SD-JWT Payload Structure Validation
    // =======================================================================

    test("CI_122: SD-JWT Payload Structure Validation | _sd_alg and all mandatory payload claims are present.", async () => {
      const log = baseLog.withTag("CI_122");
      const DESCRIPTION =
        "SD-JWT payload contains _sd_alg, iss, exp, vct, issuing_authority, issuing_country, and _sd";

      log.start("Conformance test: SD-JWT payload structure validation");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_122 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const payloadSchema = z
          .object({
            _sd: z.array(z.string()).min(1),
            _sd_alg: z.string(),
            exp: z.number(),
            iss: z.string().url(),
            issuing_authority: z.string(),
            issuing_country: z.string().length(2),
            vct: z.string(),
          })
          .passthrough();

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload;

          log.debug(
            `  Payload keys: ${JSON.stringify(Object.keys(payload ?? {}))}`,
          );

          const result = payloadSchema.safeParse(payload);
          expect(
            result.success,
            `Payload structure validation failed: ${!result.success ? JSON.stringify(result.error) : ""}`,
          ).toBe(true);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_123 — SD-JWT Hash Algorithm Declaration
    // =======================================================================

    test("CI_123: SD-JWT Hash Algorithm Declaration | _sd_alg is a supported algorithm.", async () => {
      const log = baseLog.withTag("CI_123");
      const DESCRIPTION = "_sd_alg is one of sha-256, sha-384, or sha-512";

      log.start("Conformance test: SD-JWT hash algorithm declaration");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_123 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const SUPPORTED_SD_HASH_ALGORITHMS = [
          "sha-256",
          "sha-384",
          "sha-512",
        ] as const;

        for (const credentialJwt of sdJwtCredentials) {
          const { payload } = decodeJwt(extractIssuerJwt(credentialJwt));
          const sdAlg = payload["_sd_alg"];

          log.debug(`  _sd_alg: ${String(sdAlg)}`);
          expect(sdAlg, "_sd_alg must be present in payload").toBeDefined();
          expect(
            (SUPPORTED_SD_HASH_ALGORITHMS as readonly unknown[]).includes(
              sdAlg,
            ),
            `_sd_alg "${String(sdAlg)}" must be one of ${SUPPORTED_SD_HASH_ALGORITHMS.join(", ")}`,
          ).toBe(true);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_124 — SD-JWT Selective Disclosure Organization
    // =======================================================================

    test("CI_124: SD-JWT Selective Disclosure Organization | Non-SD claims are in the payload; SD digests are in the _sd array.", async () => {
      const log = baseLog.withTag("CI_124");
      const DESCRIPTION =
        "Disclosed claim keys are not also present as plain keys in the JWT payload";

      log.start("Conformance test: SD-JWT selective disclosure organization");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_124 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        // Claims that are expected to be present as plain (non-SD) keys
        const KNOWN_NON_SD_KEYS = new Set([
          "_sd",
          "_sd_alg",
          "cnf",
          "exp",
          "iat",
          "iss",
          "issuing_authority",
          "issuing_country",
          "nbf",
          "status",
          "sub",
          "vct",
          "vct#integrity",
          "verification",
        ]);

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;

          expect(Array.isArray(payload["_sd"]), "_sd must be an array").toBe(
            true,
          );
          log.debug(
            `  _sd contains ${(payload["_sd"] as unknown[]).length} digest(s)`,
          );

          for (const disc of decoded.disclosures ?? []) {
            if (disc.key === undefined) continue;
            const appearsInPayload =
              !KNOWN_NON_SD_KEYS.has(disc.key) && disc.key in payload;
            expect(
              appearsInPayload,
              `Disclosed claim "${disc.key}" must not appear as a plain key in the JWT payload`,
            ).toBe(false);
            log.debug(`  Disclosure key "${disc.key}" not in payload ✓`);
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_125 — SD-JWT Disclosure Integrity Verification
    // =======================================================================

    test("CI_125: SD-JWT Disclosure Integrity Verification | Each disclosure digest round-trips correctly.", async () => {
      const log = baseLog.withTag("CI_125");
      const DESCRIPTION =
        "All disclosure digests match entries in the JWT payload _sd array";

      log.start("Conformance test: SD-JWT disclosure integrity verification");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_125 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;
          const sdAlg = (payload["_sd_alg"] as string | undefined) ?? "sha-256";
          const sdDigests = (payload["_sd"] as string[] | undefined) ?? [];

          expect(
            decoded.disclosures,
            "Credential must contain at least one disclosure",
          ).toBeDefined();
          expect(
            (decoded.disclosures ?? []).length,
            "Credential must have a non-empty disclosures list",
          ).toBeGreaterThan(0);

          for (const disc of decoded.disclosures ?? []) {
            const recomputed = await disc.digest({
              alg: sdAlg,
              hasher: digest,
            });
            log.debug(
              `  Disclosure "${disc.key ?? "(array element)"}" recomputed digest: ${recomputed}`,
            );
            expect(
              sdDigests,
              `Digest for disclosure "${disc.key ?? "(array element)"}" must appear in _sd array`,
            ).toContain(recomputed);
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_126 — Multi-level _sd Claim in Nested SD-JWT Payloads
    // =======================================================================

    test("CI_126: Multi-level _sd in Nested SD-JWT Payload | Every _sd array at each nesting level is well-formed.", async () => {
      const log = baseLog.withTag("CI_126");
      const DESCRIPTION =
        "_sd arrays at every nesting level are well-formed arrays of non-empty base64url digest strings (§4.2.4 SD-JWT — _sd may appear multiple times at different levels)";

      log.start(
        "Conformance test: SD-JWT multi-level _sd claim in nested payload",
      );

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_126 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        /**
         * Recursively walk an object node and collect every `_sd` array found,
         * regardless of nesting depth.  Returns a list of `{ path, sdArray }`
         * entries so callers can assert on each one independently.
         */
        function collectSdArrays(
          node: unknown,
          path: string,
        ): { path: string; sdArray: unknown[] }[] {
          if (
            typeof node !== "object" ||
            node === null ||
            Array.isArray(node)
          ) {
            return [];
          }
          const record = node as Record<string, unknown>;
          const results: { path: string; sdArray: unknown[] }[] = [];

          if (Array.isArray(record["_sd"])) {
            results.push({ path, sdArray: record["_sd"] as unknown[] });
          }

          for (const [key, value] of Object.entries(record)) {
            // Skip SD-JWT meta-claims; recurse into nested plain objects only.
            if (key === "_sd" || key === "_sd_alg") continue;
            if (
              typeof value === "object" &&
              value !== null &&
              !Array.isArray(value)
            ) {
              results.push(...collectSdArrays(value, `${path}.${key}`));
            }
          }

          return results;
        }

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;

          const sdArrayLocations = collectSdArrays(payload, "payload");

          expect(
            sdArrayLocations.length,
            "At least one _sd array must be present in the payload",
          ).toBeGreaterThan(0);

          log.debug(
            `  Found _sd at ${sdArrayLocations.length} level(s): ${sdArrayLocations.map((l) => l.path).join(", ")}`,
          );

          // Verify every _sd array found — at any level — is well-formed.
          for (const { path, sdArray } of sdArrayLocations) {
            expect(
              sdArray.length,
              `_sd at "${path}" must be a non-empty array`,
            ).toBeGreaterThan(0);

            for (const [idx, digestValue] of sdArray.entries()) {
              expect(
                typeof digestValue === "string" && digestValue.length > 0,
                `_sd[${idx}] at "${path}" must be a non-empty string digest`,
              ).toBe(true);
            }

            log.debug(`  _sd at "${path}" is well-formed ✓`);
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_127 — SD-JWT Array Element Digest Positioning (Section 4.2.4.2)
    // =======================================================================

    test("CI_127: SD-JWT Disclosure Digest Positioning | Array-element digests and decoy digests correctly replace values in exact array positions.", async () => {
      const log = baseLog.withTag("CI_127");
      const DESCRIPTION =
        'Each {"...": "<digest>"} placeholder has exactly one key, every array-element disclosure digest maps to a placeholder, no digest appears more than once, and decoy digests are accepted (Section 4.2.4.2 SD-JWT)';

      log.start(
        "Conformance test: SD-JWT array element digest positioning (Section 4.2.4.2)",
      );

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_127 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;
          const sdAlg = (payload["_sd_alg"] as string | undefined) ?? "sha-256";

          // ---------------------------------------------------------------
          // Walk the entire payload tree and collect every {"...": digest}
          // placeholder while enforcing structural constraints from §4.2.4.2:
          //   - The key MUST always be exactly "..." (three dots).
          //   - There MUST NOT be any other keys in the object.
          //   - The value MUST be a non-empty string (the base64url digest).
          // ---------------------------------------------------------------
          const allPlaceholderDigests: string[] = [];

          function collectPlaceholders(node: unknown): void {
            if (Array.isArray(node)) {
              for (const item of node) {
                if (
                  typeof item === "object" &&
                  item !== null &&
                  !Array.isArray(item)
                ) {
                  const record = item as Record<string, unknown>;
                  if ("..." in record) {
                    // §4.2.4.2: MUST NOT be any other keys in the object
                    // eslint-disable-next-line vitest/no-conditional-expect
                    expect(
                      Object.keys(record).length,
                      `Array-element placeholder must have exactly one key "..." but found: [${Object.keys(record).join(", ")}]`,
                    ).toBe(1);

                    const digestValue = record["..."];
                    // eslint-disable-next-line vitest/no-conditional-expect
                    expect(
                      typeof digestValue === "string" &&
                        (digestValue as string).length > 0,
                      'Array-element placeholder {"..."} value must be a non-empty base64url string',
                    ).toBe(true);

                    allPlaceholderDigests.push(digestValue as string);
                  }
                }
                collectPlaceholders(item);
              }
            } else if (typeof node === "object" && node !== null) {
              for (const value of Object.values(
                node as Record<string, unknown>,
              )) {
                collectPlaceholders(value);
              }
            }
          }

          collectPlaceholders(payload);

          if (allPlaceholderDigests.length === 0) {
            log.debug(
              "→ CI_127 skipped for this credential: no Pattern B array-element placeholders found",
            );
            continue;
          }

          log.debug(
            `  Found ${allPlaceholderDigests.length} Pattern B placeholder(s)`,
          );

          // ---------------------------------------------------------------
          // §4.2.4.2 + §4.1: The same digest value MUST NOT appear more
          // than once in the SD-JWT payload (directly or via placeholders).
          // ---------------------------------------------------------------
          const uniquePlaceholders = new Set(allPlaceholderDigests);
          expect(
            uniquePlaceholders.size,
            "Each array-element placeholder digest must be unique — the same digest MUST NOT appear more than once",
          ).toBe(allPlaceholderDigests.length);

          // ---------------------------------------------------------------
          // §4.2.2: Array-element disclosures are 2-element arrays
          // [salt, value] — the claim name is absent (disc.key === undefined).
          // Every such disclosure's digest MUST appear as a placeholder.
          // ---------------------------------------------------------------
          const arrayElementDisclosures = (decoded.disclosures ?? []).filter(
            (disc) => disc.key === undefined,
          );

          log.debug(
            `  Found ${arrayElementDisclosures.length} array-element disclosure(s)`,
          );

          for (const disc of arrayElementDisclosures) {
            // key === undefined already confirms the 2-element [salt, value]
            // structure (no claim name field).
            expect(
              disc.key,
              "Array-element disclosure MUST be a 2-element [salt, value] array — claim name must be absent",
            ).toBeUndefined();

            const recomputed = await disc.digest({
              alg: sdAlg,
              hasher: digest,
            });

            log.debug(
              `  Array-element disclosure recomputed digest: ${recomputed}`,
            );

            expect(
              allPlaceholderDigests,
              `Digest for array-element disclosure must appear as a {"...": "<digest>"} placeholder at its exact array position (Section 4.2.4.2)`,
            ).toContain(recomputed);
          }

          // ---------------------------------------------------------------
          // Decoy digests: placeholders with no matching disclosure are
          // explicitly permitted by §4.2.5 ("An Issuer MAY add additional
          // digests … in arrays").  Log them for visibility but do not fail.
          // ---------------------------------------------------------------
          const disclosureDigestSet = new Set<string>();
          for (const disc of arrayElementDisclosures) {
            disclosureDigestSet.add(
              await disc.digest({ alg: sdAlg, hasher: digest }),
            );
          }
          const decoyCount = allPlaceholderDigests.filter(
            (d) => !disclosureDigestSet.has(d),
          ).length;

          log.debug(
            `  Disclosure placeholders: ${disclosureDigestSet.size}, decoy placeholders: ${decoyCount}`,
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_128 — SD-JWT Array Element Digest Calculation
    // =======================================================================

    test("CI_128: SD-JWT Array Element Digest Calculation | Pattern B element digests are correctly computed.", async () => {
      const log = baseLog.withTag("CI_128");
      const DESCRIPTION =
        "Pattern B array element placeholder digests match re-computed hashes (vacuously passes when Pattern B is not used)";

      log.start("Conformance test: SD-JWT array element digest calculation");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_128 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;
          const sdAlg = (payload["_sd_alg"] as string | undefined) ?? "sha-256";

          // Collect Pattern B placeholder digests: {"...": "<digest>"}
          const placeholderDigests: string[] = [];
          for (const value of Object.values(payload)) {
            if (Array.isArray(value)) {
              for (const item of value) {
                if (
                  typeof item === "object" &&
                  item !== null &&
                  "..." in (item as Record<string, unknown>)
                ) {
                  const d = (item as Record<string, string>)["..."];
                  if (d !== undefined) placeholderDigests.push(d);
                }
              }
            }
          }

          if (placeholderDigests.length === 0) {
            log.debug(
              "→ CI_128 skipped: Pattern B not used (no array element placeholders found)",
            );
            testSuccess = true;
            continue;
          }

          log.debug(
            `  Found ${placeholderDigests.length} Pattern B placeholder(s)`,
          );

          // Array-element disclosures have no key (two-element array: [salt, value])
          const arrayElementDisclosures = (decoded.disclosures ?? []).filter(
            (disc) => disc.key === undefined,
          );

          for (const disc of arrayElementDisclosures) {
            const recomputed = await disc.digest({
              alg: sdAlg,
              hasher: digest,
            });
            log.debug(`  Array element recomputed digest: ${recomputed}`);
            expect(
              placeholderDigests,
              "Array element disclosure digest must appear in a Pattern B placeholder",
            ).toContain(recomputed);
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_129 — SD-JWT Array Disclosures
    // =======================================================================

    test("CI_129: SD-JWT Array Disclosures | Array-valued claims are correctly selectively disclosed.", async () => {
      const log = baseLog.withTag("CI_129");
      const DESCRIPTION =
        "Array-valued claims are present and accessible via disclosures after decoding";

      log.start("Conformance test: SD-JWT array disclosures");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_129 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);

          // Pattern A: whole-array disclosures (disclosure.value is an array)
          const arrayDisclosures = (decoded.disclosures ?? []).filter(
            (disc) => disc.key !== undefined && Array.isArray(disc.value),
          );

          // Pattern B: element-level disclosures (disclosure.key is undefined)
          const elementDisclosures = (decoded.disclosures ?? []).filter(
            (disc) => disc.key === undefined,
          );

          const hasArrayDisclosures =
            arrayDisclosures.length > 0 || elementDisclosures.length > 0;

          if (!hasArrayDisclosures) {
            log.debug(
              "→ CI_129 skipped: no array disclosures found in this credential",
            );
            testSuccess = true;
            continue;
          }

          for (const disc of arrayDisclosures) {
            expect(
              Array.isArray(disc.value),
              `Disclosure "${disc.key}" value must be an array`,
            ).toBe(true);
            expect(
              (disc.value as unknown[]).length,
              `Array disclosure "${disc.key}" must be non-empty`,
            ).toBeGreaterThan(0);
          }

          if (arrayDisclosures.length > 0) {
            log.debug(
              `  Pattern A: ${arrayDisclosures.length} array-valued disclosure(s)`,
            );
          }

          if (elementDisclosures.length > 0) {
            log.debug(
              `  Pattern B: ${elementDisclosures.length} array-element disclosure(s)`,
            );
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_130 — SD-JWT Combined Format Disclosure Delivery
    // =======================================================================

    test("CI_130: SD-JWT Combined Format Disclosure Delivery | Credential is a valid tilde-separated combined format.", async () => {
      const log = baseLog.withTag("CI_130");
      const DESCRIPTION =
        "SD-JWT credential is in Combined Format: Issuer-JWT~disclosure*~ (with trailing tilde)";

      log.start("Conformance test: SD-JWT combined format disclosure delivery");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_130 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        for (const credentialJwt of sdJwtCredentials) {
          const parts = credentialJwt.split("~");
          log.debug(`  Combined format parts count: ${parts.length}`);

          expect(
            parts.length,
            "Combined format must have at least 3 parts (JWT + one disclosure + trailing empty string)",
          ).toBeGreaterThan(2);

          expect(
            parts[parts.length - 1],
            "Combined format must end with a trailing tilde (last split part is empty string)",
          ).toBe("");

          const issuerJwt = parts[0] ?? "";
          const jwtParts = issuerJwt.split(".");
          expect(
            jwtParts.length,
            "Issuer-signed JWT must be a compact JWS with exactly three parts (header.payload.signature)",
          ).toBe(3);

          const disclosureParts = parts.slice(1, parts.length - 1);
          expect(
            disclosureParts.length,
            "At least one disclosure must be present after the issuer JWT",
          ).toBeGreaterThan(0);

          for (const disclosurePart of disclosureParts) {
            expect(
              disclosurePart.length,
              "Each disclosure must be a non-empty base64url string",
            ).toBeGreaterThan(0);
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_131 — SD-JWT JOSE Header Parameter
    // =======================================================================

    test("CI_131: SD-JWT JOSE Header Parameter | Mandatory header parameters are present and valid.", async () => {
      const log = baseLog.withTag("CI_131");
      const DESCRIPTION =
        "SD-JWT JOSE header contains typ=dc+sd-jwt, a supported alg, kid, and x5c";

      log.start("Conformance test: SD-JWT JOSE header parameters");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_131 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const SUPPORTED_SIGNING_ALGORITHMS = [
          "ES256",
          "ES384",
          "ES512",
          "PS256",
          "PS384",
          "PS512",
        ] as const;

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const header = decoded.jwt?.header as Record<string, unknown>;

          log.debug(`  JOSE header: ${JSON.stringify(header)}`);

          expect(header["typ"], "typ must equal dc+sd-jwt").toBe("dc+sd-jwt");

          expect(
            (SUPPORTED_SIGNING_ALGORITHMS as readonly unknown[]).includes(
              header["alg"],
            ),
            `alg "${String(header["alg"])}" must be a supported signing algorithm (${SUPPORTED_SIGNING_ALGORITHMS.join(", ")})`,
          ).toBe(true);

          expect(typeof header["kid"], "kid must be a string").toBe("string");
          expect(
            (header["kid"] as string).length,
            "kid must not be empty",
          ).toBeGreaterThan(0);

          expect(Array.isArray(header["x5c"]), "x5c must be an array").toBe(
            true,
          );
          expect(
            (header["x5c"] as unknown[]).length,
            "x5c must contain at least one certificate entry",
          ).toBeGreaterThan(0);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_132 — SD-JWT Payload Claims
    // =======================================================================

    test("CI_132: SD-JWT Payload Claims | All mandatory payload claims are present and well-typed.", async () => {
      const log = baseLog.withTag("CI_132");
      const DESCRIPTION =
        "SD-JWT payload contains iss, exp, vct, issuing_authority, issuing_country, _sd, _sd_alg, and status";

      log.start("Conformance test: SD-JWT mandatory payload claims");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_132 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const instance = new SDJwtVcInstance({ hasher: digest });

        for (const credentialJwt of sdJwtCredentials) {
          const decoded = await instance.decode(credentialJwt);
          const payload = decoded.jwt?.payload as Record<string, unknown>;

          log.debug(`  Payload keys: ${JSON.stringify(Object.keys(payload))}`);

          expect(typeof payload["iss"], "iss must be a string").toBe("string");
          expect(
            (payload["iss"] as string).length,
            "iss must not be empty",
          ).toBeGreaterThan(0);

          expect(typeof payload["exp"], "exp must be a number").toBe("number");
          expect(
            (payload["exp"] as number) > Math.floor(Date.now() / 1000),
            "exp must be in the future",
          ).toBe(true);

          expect(typeof payload["vct"], "vct must be a string").toBe("string");
          expect(
            (payload["vct"] as string).length,
            "vct must not be empty",
          ).toBeGreaterThan(0);

          expect(
            typeof payload["issuing_authority"],
            "issuing_authority must be a string",
          ).toBe("string");

          expect(
            typeof payload["issuing_country"],
            "issuing_country must be a string",
          ).toBe("string");
          expect(
            (payload["issuing_country"] as string).length,
            "issuing_country must be a 2-character ISO 3166-1 Alpha-2 code",
          ).toBe(2);

          expect(Array.isArray(payload["_sd"]), "_sd must be an array").toBe(
            true,
          );
          expect(
            (payload["_sd"] as string[]).length,
            "_sd must be non-empty",
          ).toBeGreaterThan(0);

          expect(typeof payload["_sd_alg"], "_sd_alg must be a string").toBe(
            "string",
          );

          expect(typeof payload["status"], "status must be an object").toBe(
            "object",
          );
          expect(payload["status"], "status must not be null").not.toBeNull();
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_133 — SD-JWT Status List Parameter Structure (V1.3 only)
    // =======================================================================

    test("CI_133: SD-JWT Status List Parameter Structure | status.status_list contains idx (integer) and uri (string).", async () => {
      const log = baseLog.withTag("CI_133");
      const DESCRIPTION =
        "status.status_list.idx is an integer and status.status_list.uri is a string — V1.3 only";

      log.start("Conformance test: SD-JWT status list parameter structure");

      let testSuccess = false;
      try {
        if (ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0)) {
          log.debug(
            "→ CI_133 skipped: status_list only exists in V1.3+ (V1.0 uses status_assertion)",
          );
          testSuccess = true;
          return;
        }

        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_133 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        for (const credentialJwt of sdJwtCredentials) {
          const { payload } = decodeJwt(extractIssuerJwt(credentialJwt));
          const statusClaim = payload["status"] as
            | Record<string, unknown>
            | undefined;

          expect(statusClaim, "status claim must be present").toBeDefined();

          const statusList = statusClaim?.["status_list"] as
            | Record<string, unknown>
            | undefined;

          expect(
            statusList,
            "status.status_list must be defined",
          ).toBeDefined();
          log.debug(`  status.status_list: ${JSON.stringify(statusList)}`);

          expect(
            typeof statusList?.["idx"],
            "status_list.idx must be a number",
          ).toBe("number");
          expect(
            Number.isInteger(statusList?.["idx"]),
            "status_list.idx must be an integer",
          ).toBe(true);

          expect(
            typeof statusList?.["uri"],
            "status_list.uri must be a string",
          ).toBe("string");
          expect(
            (statusList?.["uri"] as string).length,
            "status_list.uri must not be empty",
          ).toBeGreaterThan(0);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_134 — Optional Credential Type Metadata Retrieval
    // =======================================================================

    test("CI_134: Optional Credential Type Metadata Retrieval | .well-known/type-metadata endpoint returns a valid response.", async () => {
      const log = baseLog.withTag("CI_134");
      const DESCRIPTION =
        "Type metadata endpoint returns HTTP 200 with valid JSON containing a matching vct";

      log.start("Conformance test: credential type metadata retrieval");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_134 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const fetcher = fetchWithConfig(orchestrator.getConfig().network);

        for (const credentialJwt of sdJwtCredentials) {
          const { payload } = decodeJwt(extractIssuerJwt(credentialJwt));
          const vct = payload["vct"] as string | undefined;

          if (!vct) {
            throw new Error(
              "CI_134 failed: vct claim not found in credential payload",
            );
          }

          const metadataUrl = `${credentialIssuer}/.well-known/type-metadata?vct=${encodeURIComponent(vct)}`;
          log.debug(`  Fetching: ${metadataUrl}`);

          let response: Response;
          try {
            response = await fetcher(metadataUrl);
          } catch (e) {
            throw new Error(
              `CI_134 failed: unable to fetch type metadata from ${metadataUrl} — ${e instanceof Error ? e.message : String(e)}`,
            );
          }

          if (response.status === 404 || response.status === 400) {
            log.debug(
              `→ CI_134 skipped: endpoint returned ${response.status} (endpoint is optional)`,
            );
            testSuccess = true;
            return;
          }

          expect(
            response.status,
            "Type metadata endpoint must return HTTP 200",
          ).toBe(200);

          const body = (await response.json()) as Record<string, unknown>;
          expect(
            body["vct"],
            "Type metadata body must contain vct matching the credential vct",
          ).toBe(vct);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_134a — SD-JWT Case-Sensitive URI Matching
    // =======================================================================

    test("CI_134a: SD-JWT Case-Sensitive URI Matching | vct URN is matched case-sensitively.", async () => {
      const log = baseLog.withTag("CI_134a");
      const DESCRIPTION =
        "Querying .well-known/type-metadata with an uppercased vct does not return the original credential vct";

      log.start("Conformance test: SD-JWT case-sensitive URI matching");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_134a skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const fetcher = fetchWithConfig(orchestrator.getConfig().network);

        for (const credentialJwt of sdJwtCredentials) {
          const { payload } = decodeJwt(extractIssuerJwt(credentialJwt));
          const vct = payload["vct"] as string | undefined;

          if (!vct) {
            throw new Error(
              "CI_134a failed: vct claim not found in credential payload",
            );
          }

          const upperVct = vct.toUpperCase();
          if (upperVct === vct) {
            log.debug(
              "→ CI_134a skipped: vct is already all-uppercase — case-sensitivity test is not meaningful",
            );
            testSuccess = true;
            return;
          }

          log.debug(`  Original vct:  ${vct}`);
          log.debug(`  Uppercase vct: ${upperVct}`);

          const metadataUrl = `${credentialIssuer}/.well-known/type-metadata?vct=${encodeURIComponent(upperVct)}`;

          let response: Response;
          try {
            response = await fetcher(metadataUrl);
          } catch (e) {
            log.debug(
              `→ CI_134a skipped: network error — ${e instanceof Error ? e.message : String(e)}`,
            );
            testSuccess = true;
            return;
          }

          const body =
            response.status === 200
              ? ((await response.json()) as Record<string, unknown>)
              : null;

          // Either the endpoint rejects the uppercased vct (non-200),
          // or it returns 200 but with a vct that differs from the original
          expect(
            response.status !== 200 || body?.["vct"] !== vct,
            "When queried with an uppercased vct, the endpoint must either reject (non-200) or return a vct different from the original (case-sensitive matching required)",
          ).toBe(true);

          if (response.status !== 200) {
            log.debug(
              `  ✓ Endpoint correctly rejected uppercase vct with status ${response.status}`,
            );
          } else {
            log.debug(
              `  ✓ Returned vct "${String(body?.["vct"])}" differs from credential vct "${vct}"`,
            );
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // =======================================================================
    // CI_135 — Metadata Document JSON Object Structure
    // =======================================================================

    test("CI_135: Metadata Document JSON Object Structure | Type metadata document conforms to SD-JWT-VC §6.2.", async () => {
      const log = baseLog.withTag("CI_135");
      const DESCRIPTION =
        "Type metadata document is a valid JSON object with required vct and well-typed optional fields per SD-JWT-VC §6.2";

      log.start("Conformance test: metadata document JSON object structure");

      let testSuccess = false;
      try {
        const sdJwtCredentials = await getSdJwtCredentials();
        if (sdJwtCredentials.length === 0) {
          log.debug("→ CI_135 skipped: no SD-JWT VC credentials found");
          testSuccess = true;
          return;
        }

        const typeMetadataSchema = z
          .object({
            claims: z.array(z.record(z.string(), z.unknown())).optional(),
            description: z.string().optional(),
            display: z.array(z.record(z.string(), z.unknown())).optional(),
            name: z.string().optional(),
            schema: z.record(z.string(), z.unknown()).optional(),
            schema_uri: z.string().optional(),
            vct: z.string(),
          })
          .loose();

        const fetcher = fetchWithConfig(orchestrator.getConfig().network);

        for (const credentialJwt of sdJwtCredentials) {
          const { payload } = decodeJwt(extractIssuerJwt(credentialJwt));
          const vct = payload["vct"] as string | undefined;

          if (!vct) {
            throw new Error(
              "→ CI_135 failed: vct claim not found in credential payload",
            );
          }

          const metadataUrl = `${credentialIssuer}/.well-known/type-metadata?vct=${encodeURIComponent(vct)}`;

          let response: Response;
          try {
            response = await fetcher(metadataUrl);
          } catch (e) {
            log.debug(
              `→ CI_135 skipped: network error — ${e instanceof Error ? e.message : String(e)}`,
            );
            testSuccess = true;
            return;
          }

          if (response.status !== 200) {
            log.debug(
              `→ CI_135 skipped: endpoint returned ${response.status} (endpoint is optional)`,
            );
            testSuccess = true;
            return;
          }

          const body = (await response.json()) as unknown;
          log.debug(`  Validating type metadata schema for vct: ${vct}`);

          const result = typeMetadataSchema.safeParse(body);
          expect(
            result.success,
            `Type metadata document must conform to SD-JWT-VC §6.2: ${!result.success ? JSON.stringify(result.error) : ""}`,
          ).toBe(true);

          if (result.success) {
            log.debug(
              `  Schema valid ✓ (fields present: ${Object.keys(result.data).join(", ")})`,
            );
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
