/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { decodeJwt as sdJwtDecodeJwt } from "@sd-jwt/decode";
import { StatusList } from "@sd-jwt/jwt-status-list";
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import { fetchWithConfig } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { CredentialRequestResponse } from "@/step/issuance";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("StatusList");

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Status List Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let credentialResponse: CredentialRequestResponse;
    const ioWalletSdkConfig: IoWalletSdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
    });
    // Extracted from the issued credential's status.status_list claim
    let statusListUri: string | undefined;
    let credentialIdx: number | undefined;
    // Fetched Status List JWT and parsed parts
    let statusListJwt: string | undefined;
    let statusListResponseStatus: number | undefined;
    let statusListContentType: null | string = null;
    let statusListContentEncoding: null | string = null;
    let statusListBits: number | undefined;
    let statusListLst: string | undefined;
    let decompressedList: StatusList | undefined;

    // -----------------------------------------------------------------------
    // Helper: extract issuer-signed JWT from Combined Format (splits on ~)
    // -----------------------------------------------------------------------

    function extractIssuerJwt(combinedFormat: string): string {
      return combinedFormat.split("~")[0] ?? "";
    }

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential configuration
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      const result = await orchestrator.issuance();
      assertIssuanceFlowSuccess(result);
      credentialResponse = result.credentialResponse;

      if (!ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0)) {
        for (const credObj of credentialResponse.response?.credentials ?? []) {
          const issuerJwt = extractIssuerJwt(credObj.credential);
          if (!issuerJwt) continue;
          const { payload } = sdJwtDecodeJwt(issuerJwt);
          const statusClaim = payload["status"] as
            | Record<string, unknown>
            | undefined;
          const slClaim = statusClaim?.["status_list"] as
            | undefined
            | { idx: number; uri: string };
          if (slClaim?.uri) {
            statusListUri = slClaim.uri;
            credentialIdx = slClaim.idx;
            break;
          }
        }

        if (statusListUri) {
          const fetcher = fetchWithConfig(orchestrator.getConfig().network);
          const response = await fetcher(statusListUri);
          statusListResponseStatus = response.status;
          statusListContentType = response.headers.get("content-type");
          statusListContentEncoding = response.headers.get("content-encoding");
          statusListJwt = await response.text();

          const jwtPayload = decodeJwt(statusListJwt);
          const slPayloadClaim = jwtPayload["status_list"] as
            | undefined
            | { bits: number; lst: string };
          if (slPayloadClaim) {
            statusListBits = slPayloadClaim.bits;
            statusListLst = slPayloadClaim.lst;
            decompressedList = StatusList.decompressStatusList(
              statusListLst,
              statusListBits as 1 | 2 | 4 | 8,
            );
          }
        }
      }
    });

    useTestSummary(baseLog, testConfig.name);

    // =======================================================================
    // CI_175 — OAuth Status List Support for Long-Lived Credentials
    // =======================================================================

    test(
      "CI_175: OAuth Status List Support | Tool queries the Status List endpoint using uri from status.status_list",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_175");
        const DESCRIPTION =
          "Status List endpoint is reachable using the URI from the credential's status.status_list claim";

        log.start(
          "Conformance test: Status List endpoint queryable via credential URI",
        );

        let testSuccess = false;
        try {
          if (!statusListUri || statusListResponseStatus === undefined)
            throw new Error("missing uri in stasus_list");

          log.debug(`→ Status List URI from credential: ${statusListUri}`);
          log.debug(`  HTTP response status: ${statusListResponseStatus}`);

          expect(
            statusListResponseStatus,
            "Status List endpoint MUST return HTTP 2xx",
          ).toBeGreaterThanOrEqual(200);
          expect(
            statusListResponseStatus,
            "Status List endpoint MUST return HTTP 2xx",
          ).toBeLessThan(300);
          expect(
            statusListJwt,
            "Status List response body MUST be a non-empty JWT string",
          ).toBeTruthy();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_176 — Digital Credential Index Allocation and Status Mapping
    // =======================================================================

    test(
      "CI_176: Digital Credential Index Allocation | idx in the credential is a valid position in the Status List byte array",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_176");
        const DESCRIPTION =
          "Credential idx is a non-negative integer corresponding to a valid entry in the Status List byte array";

        log.start("Conformance test: Status List index allocation validity");

        let testSuccess = false;
        try {
          if (credentialIdx === undefined || !decompressedList)
            throw new Error("missing idx in status_list");

          const idx = credentialIdx as number;
          const list = decompressedList as StatusList;

          log.debug(`→ credential idx: ${idx}`);

          expect(Number.isInteger(idx), "idx MUST be an integer").toBe(true);
          expect(
            idx,
            "idx MUST be a non-negative integer",
          ).toBeGreaterThanOrEqual(0);

          const statusAtIdx = list.getStatus(idx);
          expect(
            statusAtIdx,
            `Status List MUST contain a valid entry at idx=${idx}`,
          ).toBeDefined();
          expect(
            typeof statusAtIdx,
            "Status value at idx MUST be a number",
          ).toBe("number");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_177 — Status List Token Cryptographic Format
    // =======================================================================

    test(
      "CI_177: Status List Token Cryptographic Format | Status List Token is a signed JWT with typ=statuslist+jwt",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_177");
        const DESCRIPTION =
          "Status List Token is a cryptographically signed JWT (typ=statuslist+jwt, valid x5c signature)";

        log.start(
          "Conformance test: Status List Token JWT cryptographic format",
        );

        let testSuccess = false;
        try {
          if (!statusListJwt)
            throw new Error("could not load status_list response");

          const jwt = statusListJwt as string;
          const header = decodeProtectedHeader(jwt);
          log.debug(`  JWT header: ${JSON.stringify(header)}`);

          expect(header.typ, "typ MUST be 'statuslist+jwt'").toBe(
            "statuslist+jwt",
          );

          const x5c = header.x5c as string[] | undefined;
          expect(
            Array.isArray(x5c) && x5c.length > 0,
            "x5c MUST be present and non-empty for signature verification",
          ).toBe(true);

          expect(typeof header.alg, "alg MUST be present as a string").toBe(
            "string",
          );
          const alg = header.alg as string;
          const leafCert = (x5c as string[])[0];
          const pem = `-----BEGIN CERTIFICATE-----\n${leafCert}\n-----END CERTIFICATE-----`;
          const publicKey = await importX509(pem, alg);

          await expect(
            jwtVerify(jwt, publicKey, { typ: "statuslist+jwt" }),
            "JWT signature MUST be valid against the x5c leaf certificate",
          ).resolves.toBeDefined();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_178 — Status List Bit Configuration
    // =======================================================================

    test(
      "CI_178: Status List Bit Configuration | bits per credential entry is one of {1, 2, 4, 8}",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_178");
        const DESCRIPTION =
          "Status List bits-per-entry value is one of the spec-defined values {1, 2, 4, 8}";

        log.start("Conformance test: Status List bits per entry");

        let testSuccess = false;
        try {
          if (statusListBits === undefined)
            throw new Error("could not load status bits");

          const bits = statusListBits as number;
          log.debug(`→ bits per entry: ${bits}`);

          const VALID_BITS = [1, 2, 4, 8];
          expect(
            VALID_BITS.includes(bits),
            `bits MUST be one of {1, 2, 4, 8}; got ${bits}`,
          ).toBe(true);
          expect(Number.isInteger(bits), "bits MUST be an integer").toBe(true);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_179 — Status List Byte Array Creation and Credential Position
    // =======================================================================

    test(
      "CI_179: Status List Byte Array | byte array is non-empty and the credential index is assigned",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_179");
        const DESCRIPTION =
          "Status List byte array is non-empty and accommodates the credential's idx";

        log.start(
          "Conformance test: Status List byte array size and index assignment",
        );

        let testSuccess = false;
        try {
          if (
            !statusListLst ||
            !decompressedList ||
            credentialIdx === undefined
          )
            throw new Error("could not load status_list response");

          const lst = statusListLst as string;
          const list = decompressedList as StatusList;
          const idx = credentialIdx as number;

          log.debug(`→ lst (compressed, base64url): ${lst.slice(0, 20)}...`);

          expect(
            lst.length,
            "Compressed status list (lst) MUST be non-empty",
          ).toBeGreaterThan(0);

          const statusAtIdx = list.getStatus(idx);
          expect(
            statusAtIdx,
            `Byte array MUST have a valid entry at credential idx=${idx}`,
          ).toBeDefined();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_180 — Status List Status Values Setting in Byte Array
    // =======================================================================

    test(
      "CI_180: Status List Status Values Setting | status at credential idx is VALID (0x00)",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_180");
        const DESCRIPTION =
          "Status value at the credential's idx is VALID (0x00) in the Status List byte array";

        log.start(
          "Conformance test: Status List status value at credential index",
        );

        let testSuccess = false;
        try {
          if (!decompressedList || credentialIdx === undefined)
            throw new Error("could not load status_list response");

          const list = decompressedList as StatusList;
          const idx = credentialIdx as number;

          const statusValue = list.getStatus(idx);
          log.debug(`→ status at idx ${idx}: ${statusValue}`);

          expect(statusValue, `Status at idx=${idx} MUST be VALID (0x00)`).toBe(
            0x00,
          );

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_181 — Status List Byte Array Compression
    // =======================================================================

    test(
      "CI_181: Status List Byte Array Compression | lst is DEFLATE/ZLIB compressed (RFC 1951/RFC 1950)",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_180");
        const DESCRIPTION =
          "Status List byte array is compressed with DEFLATE/ZLIB as required by the spec";

        log.start("Conformance test: Status List DEFLATE/ZLIB compression");

        let testSuccess = false;
        try {
          if (!statusListLst || statusListBits === undefined)
            throw new Error("could not load status_list response");

          const lst = statusListLst as string;
          const bits = statusListBits as 1 | 2 | 4 | 8;

          let decompressionSucceeded = false;
          try {
            StatusList.decompressStatusList(lst, bits);
            decompressionSucceeded = true;
          } catch {
            decompressionSucceeded = false;
          }

          expect(
            decompressionSucceeded,
            "lst field MUST be DEFLATE/ZLIB compressed and successfully decompressible",
          ).toBe(true);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_181a — Recommended Compression Level
    // =======================================================================

    test(
      "CI_181a: Recommended Compression Level | decompressed data is valid and compression is present",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_181a");
        const DESCRIPTION =
          "Status List lst decompresses to valid data; exact compression level is advisory and cannot be verified from output";

        log.start("Conformance test: Status List compression level");

        let testSuccess = false;
        try {
          if (
            !statusListLst ||
            !decompressedList ||
            statusListBits === undefined
          )
            throw new Error("could not load status_list response");

          const lst = statusListLst as string;
          const list = decompressedList as StatusList;

          log.debug(`→ lst length (compressed, base64url): ${lst.length}`);

          // Verify decompression produces valid data with an entry at index 0
          const statusAtZero = list.getStatus(0);
          expect(
            typeof statusAtZero,
            "Decompressed status list MUST have a valid entry at index 0",
          ).toBe("number");

          expect(lst.length, "Compressed lst MUST be present").toBeGreaterThan(
            0,
          );

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_182 — Status List Endpoint Availability
    // =======================================================================

    test(
      "CI_182: Status List Endpoint Availability | endpoint returns HTTP 2xx",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_182");
        const DESCRIPTION =
          "Status List endpoint is available and returns an HTTP 2xx response";

        log.start("Conformance test: Status List endpoint availability");

        let testSuccess = false;
        try {
          if (!statusListUri || statusListResponseStatus === undefined)
            throw new Error("could not load status_list response");

          log.debug(`→ Status List endpoint: ${statusListUri}`);
          log.debug(`  HTTP response status: ${statusListResponseStatus}`);

          expect(
            statusListResponseStatus,
            "Endpoint MUST return HTTP 2xx",
          ).toBeGreaterThanOrEqual(200);
          expect(
            statusListResponseStatus,
            "Endpoint MUST return HTTP 2xx",
          ).toBeLessThan(300);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_183 — Status List Status Values Definition
    // =======================================================================

    test(
      "CI_183: Status List Status Values Definition | status values are within the spec-defined range",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_183");
        const DESCRIPTION =
          "Status value at credential idx is within the spec-defined range for the configured bits value";

        log.start("Conformance test: Status List status values definition");

        let testSuccess = false;
        try {
          if (
            !decompressedList ||
            credentialIdx === undefined ||
            statusListBits === undefined
          )
            throw new Error("could not load status_list response");

          const list = decompressedList as StatusList;
          const idx = credentialIdx as number;
          const bits = statusListBits as number;

          const maxAllowed = Math.pow(2, bits) - 1;
          const statusValue = list.getStatus(idx);
          log.debug(
            `→ status at idx ${idx}: ${statusValue} (allowed range: [0, ${maxAllowed}])`,
          );

          expect(typeof statusValue, "Status value MUST be a number").toBe(
            "number",
          );
          expect(
            statusValue as number,
            "Status value MUST be >= 0",
          ).toBeGreaterThanOrEqual(0);
          expect(
            statusValue as number,
            `Status value MUST be <= ${maxAllowed} for bits=${bits}`,
          ).toBeLessThanOrEqual(maxAllowed);

          // 0x00 = VALID, 0x01 = INVALID, 0x02 = SUSPENDED, 0x03 = APPLICATION_SPECIFIC
          const specDefinedValues = [0x00, 0x01, 0x02, 0x03];
          const isSpecDefined = specDefinedValues.includes(
            statusValue as number,
          );
          log.debug(
            `  Value ${statusValue} is ${isSpecDefined ? "spec-defined" : "application-specific"}`,
          );

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_184 — Status List Optional Additional States
    // =======================================================================

    test(
      "CI_184: Status List Optional Additional States | additional state values do not exceed the bits-configured range",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_184");
        const DESCRIPTION =
          "Optional additional state values (if present) are within the bits-configured range";

        log.start("Conformance test: Status List optional additional states");

        let testSuccess = false;
        try {
          if (
            statusListBits === undefined ||
            !decompressedList ||
            credentialIdx === undefined
          )
            throw new Error("could not load status_list response");

          const list = decompressedList as StatusList;
          const idx = credentialIdx as number;
          const bits = statusListBits as number;

          const maxAllowed = Math.pow(2, bits) - 1;
          log.debug(`→ bits=${bits}, allowed value range: [0, ${maxAllowed}]`);
          log.debug(
            `  Values 0–3 are spec-defined; values 4–${maxAllowed} are application-specific (for bits=4)`,
          );

          const statusValue = list.getStatus(idx);
          expect(
            statusValue as number,
            `Status value at idx MUST be within range [0, ${maxAllowed}]`,
          ).toBeGreaterThanOrEqual(0);
          expect(
            statusValue as number,
            `Status value MUST NOT exceed max=${maxAllowed} for bits=${bits}`,
          ).toBeLessThanOrEqual(maxAllowed);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_185 — Status List Token Parameters at Endpoint
    // =======================================================================

    test(
      "CI_185: Status List Token Parameters | token contains required compliance-table claims (iss, sub, iat, status_list)",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_185");
        const DESCRIPTION =
          "Status List Token at endpoint contains required claims: iss, sub, iat, status_list (with bits and lst)";

        log.start("Conformance test: Status List Token required parameters");

        let testSuccess = false;
        try {
          if (!statusListJwt)
            throw new Error("could not load status_list response");

          const jwt = statusListJwt as string;
          const jwtPayload = decodeJwt(jwt);
          log.debug(
            `  Payload claims: ${JSON.stringify(Object.keys(jwtPayload))}`,
          );

          expect(
            typeof jwtPayload.iss,
            "iss (issuer) MUST be present as a string",
          ).toBe("string");
          expect(
            typeof jwtPayload.sub,
            "sub MUST be present as a string (Status List Token URI)",
          ).toBe("string");
          expect(typeof jwtPayload.iat, "iat MUST be present as a number").toBe(
            "number",
          );

          const slClaim = jwtPayload["status_list"] as
            | undefined
            | { bits: unknown; lst: unknown };
          expect(slClaim, "status_list claim MUST be present").toBeDefined();
          expect(
            typeof slClaim?.bits,
            "status_list.bits MUST be a number",
          ).toBe("number");
          expect(typeof slClaim?.lst, "status_list.lst MUST be a string").toBe(
            "string",
          );

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_186 — Recommended Status List Token Short-Lived Expiration
    // =======================================================================

    test(
      "CI_186: Recommended Status List Token Expiration | exp does not exceed iat + 86400 (24 h)",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_186");
        const DESCRIPTION =
          "Status List Token exp claim does not exceed iat + 86400 seconds (24-hour maximum)";

        log.start("Conformance test: Status List Token short-lived expiration");

        let testSuccess = false;
        try {
          if (!statusListJwt)
            throw new Error("could not load status_list response");

          const jwtPayload = decodeJwt(statusListJwt as string);
          const { exp, iat } = jwtPayload;

          expect(typeof iat, "iat MUST be a number").toBe("number");
          expect(exp, "exp MUST be defined").toBeDefined();
          expect(typeof exp, "exp MUST be a number").toBe("number");

          const maxExp = (iat as number) + 86400;
          log.debug(`→ iat=${iat}, exp=${exp}, iat+86400=${maxExp}`);

          expect(
            exp as number,
            `exp MUST NOT exceed iat + 86400 (24 h); exp=${exp}, max=${maxExp}`,
          ).toBeLessThanOrEqual(maxExp);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_187 — JSON-Encoded Status List Structure
    // =======================================================================

    test(
      "CI_187: JSON-Encoded Status List Structure | status_list claim matches the compliance table",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_187");
        const DESCRIPTION =
          "status_list claim has bits (integer, one of {1,2,4,8}) and lst (non-empty base64url string)";

        log.start("Conformance test: JSON-encoded Status List structure");

        let testSuccess = false;
        try {
          if (statusListBits === undefined || !statusListLst)
            throw new Error("could not load status_list response");

          const bits = statusListBits as number;
          const lst = statusListLst as string;

          log.debug(`→ status_list.bits: ${bits}`);
          log.debug(
            `→ status_list.lst (first 20 chars): ${lst.slice(0, 20)}...`,
          );

          expect(
            Number.isInteger(bits),
            "status_list.bits MUST be an integer",
          ).toBe(true);

          const VALID_BITS = [1, 2, 4, 8];
          expect(
            VALID_BITS.includes(bits),
            "status_list.bits MUST be one of {1, 2, 4, 8}",
          ).toBe(true);

          expect(typeof lst, "status_list.lst MUST be a string").toBe("string");
          expect(
            lst.length,
            "status_list.lst MUST not be empty",
          ).toBeGreaterThan(0);
          expect(
            /^[A-Za-z0-9_-]+$/.test(lst),
            "status_list.lst MUST be base64url-encoded (JWT base64url alphabet, no padding)",
          ).toBe(true);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_190 — Status List Claim JSON Object Parameters
    // =======================================================================

    test(
      "CI_190: Status List Claim JSON Object Parameters | status.status_list in credential has valid idx and uri",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_190");
        const DESCRIPTION =
          "Credential status.status_list JSON object has idx (non-negative integer) and uri (valid URL string)";

        log.start(
          "Conformance test: Credential status.status_list claim parameters",
        );

        let testSuccess = false;
        try {
          if (credentialIdx === undefined || !statusListUri)
            throw new Error("missing uri/idx in status_list");

          const idx = credentialIdx as number;
          const uri = statusListUri as string;

          log.debug(`→ status_list.idx: ${idx}`);
          log.debug(`→ status_list.uri: ${uri}`);

          expect(typeof idx, "status_list.idx MUST be a number").toBe("number");
          expect(
            Number.isInteger(idx),
            "status_list.idx MUST be an integer",
          ).toBe(true);
          expect(
            idx,
            "status_list.idx MUST be a non-negative integer",
          ).toBeGreaterThanOrEqual(0);

          expect(typeof uri, "status_list.uri MUST be a string").toBe("string");
          expect(
            uri.length,
            "status_list.uri MUST not be empty",
          ).toBeGreaterThan(0);
          expect(
            () => new URL(uri),
            "status_list.uri MUST be a valid URL",
          ).not.toThrow();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_191 — Status List Endpoint Successful Response
    // =======================================================================

    test(
      "CI_191: Status List Endpoint Successful Response | HTTP 2xx and Content-Type: application/statuslist+jwt",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_191");
        const DESCRIPTION =
          "Status List endpoint returns HTTP 2xx with Content-Type: application/statuslist+jwt";

        log.start("Conformance test: Status List endpoint response format");

        let testSuccess = false;
        try {
          if (!statusListUri || statusListResponseStatus === undefined)
            throw new Error("could not load status_list response");

          log.debug(`  HTTP status: ${statusListResponseStatus}`);
          log.debug(`  Content-Type: ${statusListContentType}`);

          expect(
            statusListResponseStatus,
            "Endpoint MUST return HTTP 2xx",
          ).toBeGreaterThanOrEqual(200);
          expect(
            statusListResponseStatus,
            "Endpoint MUST return HTTP 2xx",
          ).toBeLessThan(300);
          expect(
            statusListContentType,
            "Content-Type MUST contain 'application/statuslist+jwt'",
          ).toContain("application/statuslist+jwt");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // =======================================================================
    // CI_192 — HTTP Status List Response Gzip Content-Encoding
    // =======================================================================

    test(
      "CI_192: HTTP Status List Response Content-Encoding | response uses gzip when HTTP compression is applied",
      { skip: ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) },
      async () => {
        const log = baseLog.withTag("CI_192");
        const DESCRIPTION =
          "Status List endpoint response uses gzip when HTTP compression is applied (Content-Encoding: gzip)";

        log.start("Conformance test: Status List response Content-Encoding");

        let testSuccess = false;
        try {
          if (!statusListUri) throw new Error("missing uri in status_list");

          log.debug(`  Content-Encoding: ${statusListContentEncoding}`);

          if (!statusListContentEncoding) {
            log.info("'Content-Encoding' header missing");
            testSuccess = true;
            return log.testCompleted(DESCRIPTION, true);
          }

          expect(
            statusListContentEncoding,
            "Content-Encoding MUST be 'gzip'",
          ).toBe("gzip");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );
  });
});
