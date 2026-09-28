/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  Fetch,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { StatusList } from "@sd-jwt/jwt-status-list";
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import { evaluateStatusRequirement, parseCredential } from "@/functions";
import { fetchWithConfig } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { getCredentialResponseCredentials } from "@/step/issuance";
import { Logger } from "@/types";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("StatusList");

// ---------------------------------------------------------------------------
// Per-credential status list model
// ---------------------------------------------------------------------------

/**
 * Outcome of the status-list evaluation for a single issued credential:
 * - `exempt`  — short-lived credential legitimately issued without a status claim;
 * - `invalid` — the credential fails every status list assertion (e.g. it is
 *               long-lived but carries no `status` claim);
 * - `ready`   — status list entry resolved and Status List Token fetched.
 */
type CredentialStatusContext =
  | { detail: string; kind: "exempt"; label: string }
  | {
      entry: StatusListEntry;
      kind: "ready";
      label: string;
      statusList: StatusListData;
    }
  | { kind: "invalid"; label: string; reason: string };

type ReadyStatusListContext = Extract<
  CredentialStatusContext,
  { kind: "ready" }
>;

/** Status List Token as served by a credential's `status.status_list.uri`. */
interface StatusListData {
  /** `status_list.bits`; undefined when the token payload is not decodable. */
  bits?: number;
  contentEncoding: null | string;
  contentType: null | string;
  /** Inflated byte array; undefined when `lst` could not be decompressed. */
  decompressed?: StatusList;
  httpStatus: number;
  jwt: string;
  /** `status_list.lst`; undefined when the token payload is not decodable. */
  lst?: string;
}

/** Entry taken from a credential's `status.status_list` claim. */
interface StatusListEntry {
  idx: number;
  uri: string;
}

/**
 * Fetches and decodes the Status List Token published at `uri`.
 * HTTP facts are always captured; the payload fields are left undefined when
 * the token cannot be decoded, so that the tests asserting on them report the
 * failure with their own message instead of breaking the shared setup.
 */
async function fetchStatusListData(
  fetcher: Fetch,
  uri: string,
): Promise<StatusListData> {
  const response = await fetcher(uri);
  const jwt = await response.text();

  const statusList: StatusListData = {
    contentEncoding: response.headers.get("content-encoding"),
    contentType: response.headers.get("content-type"),
    httpStatus: response.status,
    jwt,
  };

  try {
    const claim = decodeJwt(jwt)["status_list"] as
      | undefined
      | { bits: number; lst: string };
    if (claim) {
      statusList.bits = claim.bits;
      statusList.lst = claim.lst;
      statusList.decompressed = StatusList.decompressStatusList(
        claim.lst,
        claim.bits as 1 | 2 | 4 | 8,
      );
    }
  } catch {
    // Intentionally ignored: CI_177, CI_181 and CI_185 assert on these fields.
  }

  return statusList;
}

/**
 * Parses one issued credential and resolves its Status List Token.
 *
 * @param compact         Compact-serialized credential returned by the issuer.
 * @param position        1-based position of the credential in the batch.
 * @param specVersion     IT Wallet specification version under test.
 * @param fetchStatusList Deduplicated fetcher for Status List Tokens.
 */
async function resolveCredentialStatus(
  compact: string,
  position: number,
  specVersion: ItWalletSpecsVersion,
  fetchStatusList: (uri: string) => Promise<StatusListData>,
): Promise<CredentialStatusContext> {
  const parsed = await parseCredential(compact);
  if (!parsed.credential) {
    return {
      kind: "invalid",
      label: `credential #${position}`,
      reason: `credential could not be parsed: ${parsed.error ?? "unrecognised format"}`,
    };
  }

  const label = `credential #${position} (${parsed.credential.typ})`;
  const { detail, failure, satisfied, statusClaim } = evaluateStatusRequirement(
    parsed.credential,
    specVersion,
  );

  if (!satisfied) return { kind: "invalid", label, reason: failure };
  if (statusClaim === null) return { detail, kind: "exempt", label };

  const entry =
    "status_list" in statusClaim ? statusClaim.status_list : undefined;
  if (!entry?.uri) {
    return {
      kind: "invalid",
      label,
      reason: `'status' claim carries no 'status_list' object with a 'uri' (${detail})`,
    };
  }

  try {
    return {
      entry,
      kind: "ready",
      label,
      statusList: await fetchStatusList(entry.uri),
    };
  } catch (error) {
    return {
      kind: "invalid",
      label,
      reason: `Status List Token at ${entry.uri} could not be retrieved: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Status List Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    const ioWalletSdkConfig: IoWalletSdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
    });

    // One entry per issued credential, each with its own Status List Token
    let credentialContexts: CredentialStatusContext[] = [];

    // -----------------------------------------------------------------------
    // Helper: run an assertion once per credential that carries a status list
    // -----------------------------------------------------------------------

    async function forEachStatusList(
      log: Logger,
      assertion: (context: ReadyStatusListContext) => Promise<void> | void,
    ): Promise<void> {
      expect(
        credentialContexts.length,
        "At least one credential MUST have been issued",
      ).toBeGreaterThan(0);

      for (const context of credentialContexts) {
        if (context.kind === "invalid") {
          log.error(`  ${context.label}: ${context.reason}`);
          expect(context.kind, `${context.label}: ${context.reason}`).not.toBe(
            "invalid",
          );
          continue;
        }

        if (context.kind === "exempt") {
          log.debug(
            `  ${context.label}: no 'status' claim required (${context.detail})`,
          );
          continue;
        }

        log.debug(`→ ${context.label}: status list ${context.entry.uri}`);
        await assertion(context);
      }
    }

    /** Asserts the Status List Token payload was decodable, returning its claim. */
    function requireStatusListClaim(context: ReadyStatusListContext): {
      bits: number;
      lst: string;
    } {
      const { bits, lst } = context.statusList;

      expect(
        typeof bits,
        `${context.label}: Status List Token MUST carry a numeric 'status_list.bits'`,
      ).toBe("number");
      expect(
        typeof lst,
        `${context.label}: Status List Token MUST carry a string 'status_list.lst'`,
      ).toBe("string");

      return { bits: bits as number, lst: lst as string };
    }

    /** Asserts the Status List byte array was decompressible, returning it. */
    function requireDecompressedList(
      context: ReadyStatusListContext,
    ): StatusList {
      expect(
        context.statusList.decompressed,
        `${context.label}: 'status_list.lst' MUST decompress to a byte array`,
      ).toBeDefined();

      return context.statusList.decompressed as StatusList;
    }

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential configuration
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      const result = await orchestrator.issuance();
      assertIssuanceFlowSuccess(result);

      if (ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0)) return;

      const credentials =
        getCredentialResponseCredentials(result.credentialResponse.response) ??
        [];

      const fetcher = fetchWithConfig(orchestrator.getConfig().network);
      // Credentials issued in a batch usually share a Status List Token:
      // fetch every distinct uri only once.
      const pending = new Map<string, Promise<StatusListData>>();
      const fetchStatusList = (uri: string): Promise<StatusListData> => {
        const cached = pending.get(uri) ?? fetchStatusListData(fetcher, uri);
        pending.set(uri, cached);
        return cached;
      };

      credentialContexts = await Promise.all(
        credentials.map((credentialObj, index) =>
          resolveCredentialStatus(
            credentialObj.credential,
            index + 1,
            ioWalletSdkConfig.itWalletSpecsVersion,
            fetchStatusList,
          ),
        ),
      );

      baseLog.debug(
        `Status list contexts resolved for ${credentialContexts.length} issued credential(s)`,
      );
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
          await forEachStatusList(log, ({ entry, label, statusList }) => {
            log.debug(`  Status List URI from credential: ${entry.uri}`);
            log.debug(`  HTTP response status: ${statusList.httpStatus}`);

            expect(
              statusList.httpStatus,
              `${label}: Status List endpoint MUST return HTTP 2xx`,
            ).toBeGreaterThanOrEqual(200);
            expect(
              statusList.httpStatus,
              `${label}: Status List endpoint MUST return HTTP 2xx`,
            ).toBeLessThan(300);
            expect(
              statusList.jwt,
              `${label}: Status List response body MUST be a non-empty JWT string`,
            ).toBeTruthy();
          });

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
          await forEachStatusList(log, (context) => {
            const { idx } = context.entry;
            const { label } = context;
            const list = requireDecompressedList(context);

            log.debug(`  credential idx: ${idx}`);

            expect(
              Number.isInteger(idx),
              `${label}: idx MUST be an integer`,
            ).toBe(true);
            expect(
              idx,
              `${label}: idx MUST be a non-negative integer`,
            ).toBeGreaterThanOrEqual(0);

            const statusAtIdx = list.getStatus(idx);
            expect(
              statusAtIdx,
              `${label}: Status List MUST contain a valid entry at idx=${idx}`,
            ).toBeDefined();
            expect(
              typeof statusAtIdx,
              `${label}: Status value at idx MUST be a number`,
            ).toBe("number");
          });

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
          await forEachStatusList(log, async ({ label, statusList }) => {
            const jwt = statusList.jwt;
            const header = decodeProtectedHeader(jwt);
            log.debug(`  JWT header: ${JSON.stringify(header)}`);

            expect(header.typ, `${label}: typ MUST be 'statuslist+jwt'`).toBe(
              "statuslist+jwt",
            );

            const x5c = header.x5c as string[] | undefined;
            expect(
              Array.isArray(x5c) && x5c.length > 0,
              `${label}: x5c MUST be present and non-empty for signature verification`,
            ).toBe(true);

            expect(
              typeof header.alg,
              `${label}: alg MUST be present as a string`,
            ).toBe("string");
            const alg = header.alg as string;
            const leafCert = (x5c as string[])[0];
            const pem = `-----BEGIN CERTIFICATE-----\n${leafCert}\n-----END CERTIFICATE-----`;
            const publicKey = await importX509(pem, alg);

            await expect(
              jwtVerify(jwt, publicKey, { typ: "statuslist+jwt" }),
              `${label}: JWT signature MUST be valid against the x5c leaf certificate`,
            ).resolves.toBeDefined();
          });

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
          await forEachStatusList(log, (context) => {
            const { bits } = requireStatusListClaim(context);
            const { label } = context;

            log.debug(`  bits per entry: ${bits}`);

            const VALID_BITS = [1, 2, 4, 8];
            expect(
              VALID_BITS.includes(bits),
              `${label}: bits MUST be one of {1, 2, 4, 8}; got ${bits}`,
            ).toBe(true);
            expect(
              Number.isInteger(bits),
              `${label}: bits MUST be an integer`,
            ).toBe(true);
          });

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
          await forEachStatusList(log, (context) => {
            const { lst } = requireStatusListClaim(context);
            const list = requireDecompressedList(context);
            const { idx } = context.entry;
            const { label } = context;

            log.debug(`  lst (compressed, base64url): ${lst.slice(0, 20)}...`);

            expect(
              lst.length,
              `${label}: Compressed status list (lst) MUST be non-empty`,
            ).toBeGreaterThan(0);

            const statusAtIdx = list.getStatus(idx);
            expect(
              statusAtIdx,
              `${label}: Byte array MUST have a valid entry at credential idx=${idx}`,
            ).toBeDefined();
          });

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
          await forEachStatusList(log, (context) => {
            const list = requireDecompressedList(context);
            const { idx } = context.entry;
            const { label } = context;

            const statusValue = list.getStatus(idx);
            log.debug(`  status at idx ${idx}: ${statusValue}`);

            expect(
              statusValue,
              `${label}: Status at idx=${idx} MUST be VALID (0x00)`,
            ).toBe(0x00);
          });

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
        const log = baseLog.withTag("CI_181");
        const DESCRIPTION =
          "Status List byte array is compressed with DEFLATE/ZLIB as required by the spec";

        log.start("Conformance test: Status List DEFLATE/ZLIB compression");

        let testSuccess = false;
        try {
          await forEachStatusList(log, (context) => {
            const { bits, lst } = requireStatusListClaim(context);
            const { label } = context;

            let decompressionSucceeded = false;
            try {
              StatusList.decompressStatusList(lst, bits as 1 | 2 | 4 | 8);
              decompressionSucceeded = true;
            } catch {
              decompressionSucceeded = false;
            }

            expect(
              decompressionSucceeded,
              `${label}: lst field MUST be DEFLATE/ZLIB compressed and successfully decompressible`,
            ).toBe(true);
          });

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
          await forEachStatusList(log, (context) => {
            const { lst } = requireStatusListClaim(context);
            const list = requireDecompressedList(context);
            const { label } = context;

            log.debug(`  lst length (compressed, base64url): ${lst.length}`);

            // Verify decompression produces valid data with an entry at index 0
            const statusAtZero = list.getStatus(0);
            expect(
              typeof statusAtZero,
              `${label}: Decompressed status list MUST have a valid entry at index 0`,
            ).toBe("number");

            expect(
              lst.length,
              `${label}: Compressed lst MUST be present`,
            ).toBeGreaterThan(0);
          });

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
          await forEachStatusList(log, ({ entry, label, statusList }) => {
            log.debug(`  Status List endpoint: ${entry.uri}`);
            log.debug(`  HTTP response status: ${statusList.httpStatus}`);

            expect(
              statusList.httpStatus,
              `${label}: Endpoint MUST return HTTP 2xx`,
            ).toBeGreaterThanOrEqual(200);
            expect(
              statusList.httpStatus,
              `${label}: Endpoint MUST return HTTP 2xx`,
            ).toBeLessThan(300);
          });

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
          await forEachStatusList(log, (context) => {
            const { bits } = requireStatusListClaim(context);
            const list = requireDecompressedList(context);
            const { idx } = context.entry;
            const { label } = context;

            const maxAllowed = Math.pow(2, bits) - 1;
            const statusValue = list.getStatus(idx);
            log.debug(
              `  status at idx ${idx}: ${statusValue} (allowed range: [0, ${maxAllowed}])`,
            );

            expect(
              typeof statusValue,
              `${label}: Status value MUST be a number`,
            ).toBe("number");
            expect(
              statusValue as number,
              `${label}: Status value MUST be >= 0`,
            ).toBeGreaterThanOrEqual(0);
            expect(
              statusValue as number,
              `${label}: Status value MUST be <= ${maxAllowed} for bits=${bits}`,
            ).toBeLessThanOrEqual(maxAllowed);

            // 0x00 = VALID, 0x01 = INVALID, 0x02 = SUSPENDED, 0x03 = APPLICATION_SPECIFIC
            const specDefinedValues = [0x00, 0x01, 0x02, 0x03];
            const isSpecDefined = specDefinedValues.includes(
              statusValue as number,
            );
            log.debug(
              `  Value ${statusValue} is ${isSpecDefined ? "spec-defined" : "application-specific"}`,
            );
          });

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
          await forEachStatusList(log, (context) => {
            const { bits } = requireStatusListClaim(context);
            const list = requireDecompressedList(context);
            const { idx } = context.entry;
            const { label } = context;

            const maxAllowed = Math.pow(2, bits) - 1;
            log.debug(
              `  bits=${bits}, allowed value range: [0, ${maxAllowed}]`,
            );
            log.debug(
              `  Values 0–3 are spec-defined; values 4–${maxAllowed} are application-specific (for bits=4)`,
            );

            const statusValue = list.getStatus(idx);
            expect(
              statusValue as number,
              `${label}: Status value at idx MUST be within range [0, ${maxAllowed}]`,
            ).toBeGreaterThanOrEqual(0);
            expect(
              statusValue as number,
              `${label}: Status value MUST NOT exceed max=${maxAllowed} for bits=${bits}`,
            ).toBeLessThanOrEqual(maxAllowed);
          });

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
          await forEachStatusList(log, ({ label, statusList }) => {
            const jwtPayload = decodeJwt(statusList.jwt);
            log.debug(
              `  Payload claims: ${JSON.stringify(Object.keys(jwtPayload))}`,
            );

            expect(
              typeof jwtPayload.iss,
              `${label}: iss (issuer) MUST be present as a string`,
            ).toBe("string");
            expect(
              typeof jwtPayload.sub,
              `${label}: sub MUST be present as a string (Status List Token URI)`,
            ).toBe("string");
            expect(
              typeof jwtPayload.iat,
              `${label}: iat MUST be present as a number`,
            ).toBe("number");

            const slClaim = jwtPayload["status_list"] as
              | undefined
              | { bits: unknown; lst: unknown };
            expect(
              slClaim,
              `${label}: status_list claim MUST be present`,
            ).toBeDefined();
            expect(
              typeof slClaim?.bits,
              `${label}: status_list.bits MUST be a number`,
            ).toBe("number");
            expect(
              typeof slClaim?.lst,
              `${label}: status_list.lst MUST be a string`,
            ).toBe("string");
          });

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
          await forEachStatusList(log, ({ label, statusList }) => {
            const { exp, iat } = decodeJwt(statusList.jwt);

            expect(typeof iat, `${label}: iat MUST be a number`).toBe("number");
            expect(exp, `${label}: exp MUST be defined`).toBeDefined();
            expect(typeof exp, `${label}: exp MUST be a number`).toBe("number");

            const maxExp = (iat as number) + 86400;
            log.debug(`  iat=${iat}, exp=${exp}, iat+86400=${maxExp}`);

            expect(
              exp as number,
              `${label}: exp MUST NOT exceed iat + 86400 (24 h); exp=${exp}, max=${maxExp}`,
            ).toBeLessThanOrEqual(maxExp);
          });

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
          await forEachStatusList(log, (context) => {
            const { bits, lst } = requireStatusListClaim(context);
            const { label } = context;

            log.debug(`  status_list.bits: ${bits}`);
            log.debug(
              `  status_list.lst (first 20 chars): ${lst.slice(0, 20)}...`,
            );

            expect(
              Number.isInteger(bits),
              `${label}: status_list.bits MUST be an integer`,
            ).toBe(true);

            const VALID_BITS = [1, 2, 4, 8];
            expect(
              VALID_BITS.includes(bits),
              `${label}: status_list.bits MUST be one of {1, 2, 4, 8}`,
            ).toBe(true);

            expect(
              lst.length,
              `${label}: status_list.lst MUST not be empty`,
            ).toBeGreaterThan(0);
            expect(
              /^[A-Za-z0-9_-]+$/.test(lst),
              `${label}: status_list.lst MUST be base64url-encoded (JWT base64url alphabet, no padding)`,
            ).toBe(true);
          });

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
          await forEachStatusList(log, ({ entry, label }) => {
            const { idx, uri } = entry;

            log.debug(`  status_list.idx: ${idx}`);
            log.debug(`  status_list.uri: ${uri}`);

            expect(
              typeof idx,
              `${label}: status_list.idx MUST be a number`,
            ).toBe("number");
            expect(
              Number.isInteger(idx),
              `${label}: status_list.idx MUST be an integer`,
            ).toBe(true);
            expect(
              idx,
              `${label}: status_list.idx MUST be a non-negative integer`,
            ).toBeGreaterThanOrEqual(0);

            expect(
              typeof uri,
              `${label}: status_list.uri MUST be a string`,
            ).toBe("string");
            expect(
              uri.length,
              `${label}: status_list.uri MUST not be empty`,
            ).toBeGreaterThan(0);
            expect(
              () => new URL(uri),
              `${label}: status_list.uri MUST be a valid URL`,
            ).not.toThrow();
          });

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
          await forEachStatusList(log, ({ label, statusList }) => {
            log.debug(`  HTTP status: ${statusList.httpStatus}`);
            log.debug(`  Content-Type: ${statusList.contentType}`);

            expect(
              statusList.httpStatus,
              `${label}: Endpoint MUST return HTTP 2xx`,
            ).toBeGreaterThanOrEqual(200);
            expect(
              statusList.httpStatus,
              `${label}: Endpoint MUST return HTTP 2xx`,
            ).toBeLessThan(300);
            expect(
              statusList.contentType,
              `${label}: Content-Type MUST contain 'application/statuslist+jwt'`,
            ).toContain("application/statuslist+jwt");
          });

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
          await forEachStatusList(log, ({ label, statusList }) => {
            log.debug(`  Content-Encoding: ${statusList.contentEncoding}`);

            if (!statusList.contentEncoding) {
              log.info(`  ${label}: 'Content-Encoding' header missing`);
              return;
            }

            expect(
              statusList.contentEncoding,
              `${label}: Content-Encoding MUST be 'gzip'`,
            ).toBe("gzip");
          });

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );
  });
});
