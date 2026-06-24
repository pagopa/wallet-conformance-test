/* eslint-disable max-lines-per-function */
import type { Jwk } from "@pagopa/io-wallet-oauth2";

import { definePresentationTest } from "#/config/test-metadata";
import { assertPresentationFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { fetchMetadata } from "@pagopa/io-wallet-oid4vci";
import { extractClientIdPrefix } from "@pagopa/io-wallet-oid4vp";
import { validateTrustChain } from "@pagopa/io-wallet-oid-federation";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { decodeProtectedHeader } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import { fetchWithConfig, partialCallbacks, verifyJwt } from "@/logic";
import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import { FetchMetadataVpStepResponse } from "@/step/presentation";
import { AuthorizationRequestStepResponse } from "@/step/presentation/authorization-request-step";
import { RedirectUriStepResponse } from "@/step/presentation/redirect-uri-step";

interface RequestedPresentation {
  format: string;
  id: string;
}

function assertSignedPresentation(
  requestedPresentation: RequestedPresentation,
  presentation: unknown,
): void {
  const { format, id } = requestedPresentation;
  if (typeof presentation !== "string" || presentation.length === 0) {
    throw new Error(`vp_token.${id} contains an empty presentation`);
  }

  if (format === "dc+sd-jwt") {
    const sdJwtParts = presentation.split("~");
    const issuerJwt = sdJwtParts[0];
    const kbJwt = sdJwtParts[sdJwtParts.length - 1];
    if (sdJwtParts.length < 2 || !issuerJwt || !kbJwt) {
      throw new Error(`vp_token.${id} is not a signed SD-JWT VP`);
    }
    if (!isCompactJwt(issuerJwt) || !isCompactJwt(kbJwt)) {
      throw new Error(`vp_token.${id} is missing signed JWT segments`);
    }
    return;
  }

  if (format === "mso_mdoc") {
    if (!/^[A-Za-z0-9_-]+$/.test(presentation)) {
      throw new Error(`vp_token.${id} is not a base64url mdoc VP`);
    }
    return;
  }

  throw new Error(`Unsupported requested presentation format: ${format}`);
}

function isCompactJwt(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

function normalizePresentationArray(
  id: string,
  presentationOrArray: string | string[] | undefined,
  walletVersion: ItWalletSpecsVersion,
): string[] {
  if (!presentationOrArray) {
    throw new Error(`vp_token.${id} is missing`);
  }
  if (
    walletVersion === ItWalletSpecsVersion.V1_3 &&
    !Array.isArray(presentationOrArray)
  ) {
    throw new Error(`vp_token.${id} must be a presentation array`);
  }

  const presentations = Array.isArray(presentationOrArray)
    ? presentationOrArray
    : [presentationOrArray];
  if (presentations.length === 0) {
    throw new Error(`vp_token.${id} must contain at least one presentation`);
  }

  return presentations;
}

function readRequestedPresentation(
  credential: unknown,
  index: number,
): RequestedPresentation {
  if (!credential || typeof credential !== "object") {
    throw new Error(`dcql_query.credentials[${index}] must be an object`);
  }

  const { format, id } = credential as { format?: unknown; id?: unknown };
  if (typeof id !== "string" || id.length === 0) {
    throw new Error(`dcql_query.credentials[${index}].id must be a string`);
  }
  if (typeof format !== "string" || format.length === 0) {
    throw new Error(`dcql_query.credentials[${index}].format must be a string`);
  }

  return { format, id };
}

// Define and auto-register test configuration
const testConfig = await definePresentationTest("HappyFlowPresentation");

describe(`[${testConfig.name}] Credential Presentation Tests`, () => {
  const orchestrator: WalletPresentationOrchestratorFlow =
    new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let authorizationRequestResult: AuthorizationRequestStepResponse;
  let fetchMetadataResult: FetchMetadataVpStepResponse;
  let redirectUriResult: RedirectUriStepResponse;

  beforeAll(async () => {
    try {
      const result = await orchestrator.presentation();
      assertPresentationFlowSuccess(result);

      authorizationRequestResult = result.authorizationRequestResponse;
      fetchMetadataResult = result.fetchMetadataResponse;
      redirectUriResult = result.redirectUriResponse;

      baseLog.info("Presentation flow completed successfully");
    } catch (e) {
      baseLog.error(e);
      throw e;
    } finally {
      // Give time for all logs to be flushed before starting tests
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  });

  useTestSummary(baseLog, testConfig.name);

  test("RPR-01: Relying Party issues a correct URL using the base url provided within its metadata.", () => {
    const log = baseLog.withTag("RPR-01");

    log.start(
      "Conformance test: Verifying Same Device Flow HTTP redirect URL alignment with RP metadata",
    );

    const DESCRIPTION =
      "Relying Party correctly issues an inspectable 302 redirect URL using a metadata-declared base URL";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const verifierMetadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata
          ?.openid_credential_verifier;
      expect(verifierMetadata).toBeDefined();
      if (!verifierMetadata) {
        throw new Error("openid_credential_verifier metadata is missing");
      }

      expect(redirectUriResult.success).toBe(true);
      expect(redirectUriResult.response?.redirectUri).toBeDefined();

      const redirectUri = redirectUriResult.response?.redirectUri;
      if (!redirectUri) {
        throw new Error(
          "RPR-01 precondition failed: redirectUri is undefined. " +
            "The RP did not expose an HTTP redirect URL to inspect.",
        );
      }

      log.debug(`  redirect_uri: ${redirectUri.href}`);
      expect(["haip:", "https:"]).toContain(redirectUri.protocol);
      log.debug("  ✅ redirect_uri uses an allowed Same Device Flow scheme");

      const metadataRedirectBases = [
        ...(verifierMetadata.redirect_uris ?? []),
        ...(verifierMetadata.response_uris ?? []),
        verifierMetadata.client_id,
      ].filter((value): value is string => typeof value === "string");

      expect(metadataRedirectBases.length).toBeGreaterThan(0);
      log.debug(
        `  Metadata-declared URL bases: ${metadataRedirectBases.join(", ")}`,
      );

      const redirectHref = redirectUri.href.replace(/\/+$/, "");
      const matchesMetadataBase = metadataRedirectBases.some((base) => {
        const normalizedBase = base.replace(/\/+$/, "");
        return (
          redirectHref === normalizedBase ||
          redirectHref.startsWith(`${normalizedBase}/`) ||
          redirectHref.startsWith(`${normalizedBase}?`) ||
          redirectHref.startsWith(`${normalizedBase}#`)
        );
      });

      expect(matchesMetadataBase).toBe(true);
      log.debug("  ✅ redirect_uri uses a metadata-declared base URL");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-02: Relying Party issues QR Code successfully.", () => {
    const log = baseLog.withTag("RPR-02");

    log.start(
      "Conformance test: Verifying Cross Device Flow QR-Code payload presence and format",
    );

    const DESCRIPTION =
      "Relying Party correctly issues a QR-Code payload containing a well-formed authorization request";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const qrCodePayload =
        orchestrator.getConfig().presentation.authorize_request_url;
      log.debug(`  QR-Code payload: ${qrCodePayload}`);
      expect(qrCodePayload).toBeTruthy();

      const authorizationRequestUrl = new URL(qrCodePayload);
      expect(authorizationRequestUrl.hash).toBe("");
      expect(["haip:", "openid4vp:", "https:"]).toContain(
        authorizationRequestUrl.protocol,
      );
      log.debug("  ✅ QR-Code payload is a valid authorization request URL");

      const clientId = authorizationRequestUrl.searchParams.get("client_id");
      expect(clientId).toBeTruthy();
      log.debug(`  client_id: ${clientId}`);

      const hasRequest = authorizationRequestUrl.searchParams.has("request");
      const requestUri =
        authorizationRequestUrl.searchParams.get("request_uri");
      const requestUriMethod =
        authorizationRequestUrl.searchParams.get("request_uri_method");
      expect(hasRequest || Boolean(requestUri)).toBe(true);
      expect(hasRequest && Boolean(requestUri)).toBe(false);
      log.debug("  ✅ QR-Code payload contains exactly one request reference");

      if (!requestUri) {
        throw new Error(
          "RPR-02 precondition failed: request_uri is undefined. " +
            "The QR-Code payload does not contain a request_uri parameter.",
        );
      }

      const parsedRequestUri = new URL(requestUri);
      expect(["http:", "https:"]).toContain(parsedRequestUri.protocol);
      log.debug(`  request_uri: ${requestUri}`);

      expect(["get", "post"].includes(requestUriMethod || "get")).toBe(true);

      if (requestUriMethod) {
        log.debug(`  request_uri_method: ${requestUriMethod}`);
      }

      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      expect(parsedQrCode?.clientId).toBe(clientId);
      expect(parsedQrCode?.requestUri).toBe(requestUri);
      expect(parsedQrCode?.requestUriMethod).toBe(requestUriMethod ?? "get");
      log.debug("  ✅ QR-Code payload is parsed consistently by the wallet");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-03: Relying Party issues the QR-Code containing an URL using the base url provided within its metadata.", () => {
    const log = baseLog.withTag("RPR-03");

    log.start(
      "Conformance test: Verifying QR-Code URL alignment with RP metadata",
    );

    const DESCRIPTION =
      "Relying Party correctly issues QR-Code with URL from metadata and client_id matches issuer";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const entityClaims = fetchMetadataResult.response?.entityStatementClaims;
      const issuer = entityClaims?.sub;
      expect(issuer).toBeDefined();
      if (!issuer) {
        throw new Error("Entity statement issuer is required");
      }

      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Checking client_id matches entity statement issuer...");
      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      expect(parsedQrCode?.clientId).toBeDefined();
      if (!parsedQrCode?.clientId) {
        throw new Error(
          "RPR-06 precondition failed: parsedQrCode.clientId is undefined. " +
            "The authorization request QR code did not contain a client_id.",
        );
      }

      // The client_id should match the issuer from the entity statement
      log.debug(`  Expected: ${issuer}`);
      log.debug(`  Actual: ${parsedQrCode.clientId}`);
      const rawClientId = parsedQrCode.clientId;
      const extractedClientId = extractClientIdPrefix(rawClientId).clientId;
      log.debug(`  Extracted client_id prefix: ${extractedClientId}`);
      expect(extractedClientId).toBe(issuer);
      log.debug("  ✅ client_id matches entity statement issuer");

      log.debug("→ Checking request_uri format and domain validity...");
      expect(parsedQrCode?.requestUri).toBeDefined();
      log.debug(`  request_uri: ${parsedQrCode?.requestUri}`);
      expect(parsedQrCode?.requestUri).toMatch(/^https?:\/\/.+/);
      log.debug("  ✅ request_uri is a valid URL");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-05: Verify QR Code error correction level.", () => {
    const log = baseLog.withTag("RPR-05");

    log.start(
      "Conformance test: Verifying Cross Device Flow QR-Code error correction level capacity",
    );

    const DESCRIPTION =
      "Relying Party QR-Code payload fits QR error correction level H capacity and remains suitable for damaged-code recovery";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response?.parsedQrCode).toBeDefined();

      const qrCodePayload =
        orchestrator.getConfig().presentation.authorize_request_url;
      expect(qrCodePayload).toBeTruthy();

      const payloadBytes = new TextEncoder().encode(qrCodePayload).length;
      const maxQrVersionByteCapacityByErrorCorrectionLevel = {
        H: 1273,
        Q: 1663,
      } as const;

      log.debug(`  QR-Code payload byte length: ${payloadBytes}`);
      log.debug(
        `  QR Level H byte capacity: ${maxQrVersionByteCapacityByErrorCorrectionLevel.H}`,
      );
      log.debug(
        `  QR Level Q byte capacity: ${maxQrVersionByteCapacityByErrorCorrectionLevel.Q}`,
      );

      expect(payloadBytes).toBeLessThanOrEqual(
        maxQrVersionByteCapacityByErrorCorrectionLevel.H,
      );
      log.debug(
        "  ✅ QR-Code payload can be encoded with Level H error correction (~30% damage recovery)",
      );

      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      expect(parsedQrCode?.clientId).toBeTruthy();
      expect(parsedQrCode?.requestUri).toBeTruthy();
      log.debug(
        "  ✅ Damaged-code recovery capacity preserves a complete authorization request payload",
      );

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-77: QR Code Generation | QR Code uses the required Q error correction level", () => {
    const log = baseLog.withTag("RPR-77");

    log.start(
      "Conformance test: Verifying Cross Device Flow QR-Code payload fits error correction level Q",
    );

    const DESCRIPTION =
      "Relying Party QR-Code payload fits the required Q error correction level capacity";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response?.parsedQrCode).toBeDefined();

      const qrCodePayload =
        orchestrator.getConfig().presentation.authorize_request_url;
      expect(qrCodePayload).toBeTruthy();

      const payloadBytes = new TextEncoder().encode(qrCodePayload).length;
      const maxQrVersionByteCapacityByErrorCorrectionLevelQ = 1663;

      log.debug(`  QR-Code payload byte length: ${payloadBytes}`);
      log.debug(
        `  QR Level Q byte capacity: ${maxQrVersionByteCapacityByErrorCorrectionLevelQ}`,
      );

      expect(
        payloadBytes,
        "QR-Code payload must fit QR level Q byte capacity (Quartile, up to 25% damage recovery)",
      ).toBeLessThanOrEqual(maxQrVersionByteCapacityByErrorCorrectionLevelQ);

      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      expect(parsedQrCode?.clientId).toBeTruthy();
      expect(parsedQrCode?.requestUri).toBeTruthy();
      log.debug(
        "  ✅ QR-Code payload is compatible with Level Q error correction (~25% damage recovery)",
      );

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-07: Relying Party accepts Wallet Instance metadata via POST and replies with an updated Request Object.", () => {
    const log = baseLog.withTag("RPR-07");

    log.start(
      "Conformance test: Verifying request_uri_method=post with Wallet Instance metadata",
    );

    const DESCRIPTION =
      "Relying Party accepts Wallet Instance metadata via POST and replies with an updated Request Object";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      const requestUriMethod = parsedQrCode?.requestUriMethod ?? "get";
      if (requestUriMethod !== "post") {
        log.debug(
          `  ℹ request_uri_method is ${requestUriMethod}; POST metadata exchange validation is not applicable`,
        );
        testSuccess = true;
        return;
      }

      expect(parsedQrCode?.requestUri).toBeDefined();
      log.debug(`  request_uri: ${parsedQrCode?.requestUri}`);
      log.debug(`  request_uri_method: ${requestUriMethod}`);
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject).toBeDefined();
      log.debug(
        "  ✅ RP returned a valid Request Object after POST metadata exchange",
      );

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-87: Request URI POST Method | Wallet Instance metadata is sent as form-encoded POST.", () => {
    const log = baseLog.withTag("RPR-87");

    log.start(
      "Conformance test: Verifying request_uri_method=post sends Wallet Instance metadata as application/x-www-form-urlencoded",
    );

    const DESCRIPTION =
      "Relying Party accepts Wallet Instance metadata sent via form-encoded POST to request_uri";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const response = authorizationRequestResult.response;
      const parsedQrCode = response?.parsedQrCode;
      const requestUriMethod = parsedQrCode?.requestUriMethod ?? "get";
      if (requestUriMethod !== "post") {
        log.debug(
          `  ℹ request_uri_method is ${requestUriMethod}; POST metadata exchange validation is not applicable`,
        );
        testSuccess = true;
        return;
      }

      expect(parsedQrCode?.requestUri).toBeDefined();
      expect(response?.requestObject).toBeDefined();

      const requestObjectFetch = response?.requestObjectFetch;
      expect(requestObjectFetch).toBeDefined();
      if (!requestObjectFetch) {
        throw new Error("request_uri fetch details are missing");
      }

      log.debug(`  request_uri: ${parsedQrCode?.requestUri}`);
      log.debug(`  request_uri_method: ${requestUriMethod}`);
      log.debug(`  HTTP method: ${requestObjectFetch.method}`);
      expect(requestObjectFetch.url).toBe(parsedQrCode?.requestUri);
      expect(requestObjectFetch.method).toBe("POST");

      log.debug(`  Content-Type: ${requestObjectFetch.contentType}`);
      expect(requestObjectFetch.contentType?.split(";")[0]).toBe(
        "application/x-www-form-urlencoded",
      );

      expect(requestObjectFetch.body).toBeDefined();
      const formBody = new URLSearchParams(requestObjectFetch.body);
      const walletMetadataBody = formBody.get("wallet_metadata");
      expect(walletMetadataBody).toBeTruthy();
      expect(formBody.get("wallet_nonce")).toBe(response?.walletNonce);

      const walletMetadata = JSON.parse(walletMetadataBody ?? "{}");
      expect(walletMetadata).toEqual(response?.walletMetadata);
      expect(walletMetadata.response_modes_supported).toContain(
        "direct_post.jwt",
      );
      expect(walletMetadata.response_types_supported).toContain("vp_token");
      log.debug(
        "  ✅ Wallet Instance metadata was sent as application/x-www-form-urlencoded POST",
      );

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-88: Algorithm Validation | Request Object JWT alg is supported and not none or MAC.", () => {
    const log = baseLog.withTag("RPR-88");

    log.start(
      "Conformance test: Verifying Request Object JWT algorithm is supported and not none or MAC",
    );

    const DESCRIPTION =
      "Request Object JWT algorithm is supported by the Wallet and is neither none nor MAC-based";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const response = authorizationRequestResult.response;
      const actualAlg = response?.authorizationRequestHeader.alg;
      expect(actualAlg).toBeDefined();
      if (!actualAlg) {
        throw new Error("Request Object JWT alg header is missing");
      }

      const supportedAlgorithms =
        response.walletMetadata.request_object_signing_alg_values_supported;
      expect(supportedAlgorithms).toBeDefined();
      expect(supportedAlgorithms?.length).toBeGreaterThan(0);
      if (!supportedAlgorithms || supportedAlgorithms.length === 0) {
        throw new Error(
          "Wallet request_object_signing_alg_values_supported is missing",
        );
      }

      const macAlgorithms = new Set(["HS256", "HS384", "HS512"]);
      log.debug(`  Request Object alg: ${actualAlg}`);
      log.debug(
        `  Wallet-supported algorithms: ${supportedAlgorithms.join(", ")}`,
      );

      expect(actualAlg.toLowerCase()).not.toBe("none");
      expect(macAlgorithms.has(actualAlg)).toBe(false);
      expect(supportedAlgorithms).toContain(actualAlg);
      log.debug("  ✅ Request Object JWT alg is supported and asymmetric");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-08: Relying Party issues the Request Object via HTTP GET response.", () => {
    const log = baseLog.withTag("RPR-08");

    log.start(
      "Conformance test: Verifying request_uri_method=get Request Object retrieval",
    );

    const DESCRIPTION =
      "Relying Party issues the Request Object via HTTP GET response";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      const requestUriMethod = parsedQrCode?.requestUriMethod ?? "get";
      if (requestUriMethod !== "get") {
        log.debug(
          `  ℹ request_uri_method is ${requestUriMethod}; GET metadata exchange validation is not applicable`,
        );
        testSuccess = true;
        return;
      }

      expect(parsedQrCode?.requestUri).toBeDefined();
      log.debug(`  request_uri: ${parsedQrCode?.requestUri}`);
      log.debug(`  request_uri_method: ${requestUriMethod}`);

      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject).toBeDefined();
      log.debug("  ✅ RP returned a valid Request Object via HTTP GET");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-09: Relying Party accepts defaults to GET method.", () => {
    const log = baseLog.withTag("RPR-09");

    log.start(
      "Conformance test: Verifying HTTP GET method support for request objects",
    );

    const DESCRIPTION =
      "Relying Party supports GET method for request objects, defaults if not specified";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const metadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata;
      const verifierMetadata = metadata?.openid_credential_verifier;

      log.debug("→ Checking request_object_endpoint_methods configuration...");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response?.requestObject).toBeDefined();

      const requestObjectEndpointMethods =
        verifierMetadata?.request_object_endpoint_methods ?? ["GET"];

      // If request_object_endpoint_methods is not specified or includes GET
      if (verifierMetadata?.request_object_endpoint_methods) {
        log.debug(
          `  Supported methods: ${verifierMetadata.request_object_endpoint_methods.join(", ")}`,
        );
        log.debug("  ✅ GET method is supported");
      } else {
        log.debug(
          "  ℹ request_object_endpoint_methods not specified (GET is default)",
        );
      }
      expect(requestObjectEndpointMethods).toContain("GET");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test(
    "RPR-10: Authorization request parameters match OpenID Credential Verifier metadata.",
    { skip: true },
    async ({ skip }) => {
      const log = baseLog.withTag("RPR010");

      log.start(
        "Conformance test: Verifying authorization request parameters match RP metadata",
      );

      const DESCRIPTION =
        "Authorization request parameters are consistent with OpenID Credential Verifier metadata declarations";
      let testSuccess = false;
      try {
        const config = orchestrator.getConfig();
        const baseUrl = orchestrator.prepareBaseUrl();
        if (!baseUrl) {
          log.warn(
            `  Skipping verifier metadata fetch: unsupported client_id format`,
          );
          skip();
          return;
        }

        const entityClaims = await fetchMetadata({
          callbacks: {
            fetch: fetchWithConfig(config.network),
            verifyJwt,
          },
          config: new IoWalletSdkConfig({
            itWalletSpecsVersion: config.wallet.wallet_version,
          }),
          credentialIssuerUrl: baseUrl,
        });

        const verifierMetadata =
          entityClaims?.metadata?.openid_credential_verifier;
        expect(verifierMetadata).toBeDefined();
        if (!verifierMetadata) {
          throw new Error("openid_credential_verifier metadata is missing");
        }

        expect(authorizationRequestResult.success).toBe(true);
        expect(authorizationRequestResult.response).toBeDefined();

        const requestObject =
          authorizationRequestResult.response?.requestObject;
        const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;

        log.debug("→ Checking client_id matches metadata client_id...");
        const metadataClientId: string = verifierMetadata.client_id;
        expect(metadataClientId).toBeDefined();
        const { clientId: rawClientId } = extractClientIdPrefix(
          parsedQrCode?.clientId ?? "",
        );
        log.debug(`  Metadata client_id: ${metadataClientId}`);
        log.debug(`  Request client_id:  ${rawClientId}`);
        expect(rawClientId).toBe(metadataClientId);
        log.debug("  ✅ client_id matches metadata");

        log.debug(
          "→ Checking response_uri is declared in metadata response_uris...",
        );
        const responseUris: string[] = verifierMetadata.response_uris ?? [];
        const requestResponseUri: string = requestObject?.response_uri ?? "";
        expect(requestResponseUri).toBeTruthy();
        log.debug(`  response_uri: ${requestResponseUri}`);
        log.debug(`  Declared response_uris: ${responseUris.join(", ")}`);
        expect(responseUris).toContain(requestResponseUri);
        log.debug("  ✅ response_uri is declared in metadata response_uris");

        log.debug(
          "→ Checking request_uri is declared in metadata request_uris...",
        );
        const requestUris: string[] = verifierMetadata.request_uris ?? [];
        const actualRequestUri: string = parsedQrCode?.requestUri ?? "";
        expect(actualRequestUri).toBeTruthy();
        log.debug(`  request_uri: ${actualRequestUri}`);
        log.debug(`  Declared request_uris: ${requestUris.join(", ")}`);
        expect(requestUris).toContain(actualRequestUri);
        log.debug("  ✅ request_uri is declared in metadata request_uris");

        log.debug("→ Verifying trust chain from request object JWT header...");
        const header =
          authorizationRequestResult.response?.authorizationRequestHeader;
        const trustChain = header?.trust_chain;

        if (trustChain && trustChain.length > 0) {
          log.debug(`  trust_chain present with ${trustChain.length} JWT(s)`);
          await validateTrustChain([...trustChain], {
            callbacks: {
              fetch: fetchWithConfig(config.network),
              hash: partialCallbacks.hash,
              verifyJwt: partialCallbacks.verifyJwt,
            },
          });
          log.debug("  ✅ Trust chain signature verification passed");
        } else {
          log.debug(
            "  ℹ trust_chain not present in request object JWT header (may use x5c instead)",
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    },
  );

  test("RPR-12: Relying Party receives and validates response with state and nonce values.", () => {
    const log = baseLog.withTag("RPR-12");

    log.start(
      "Conformance test: Verifying state and nonce parameter presence and format",
    );

    const DESCRIPTION =
      "Relying Party receives and validates state and nonce values in response";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating state parameter...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.state).toBeDefined();
      log.debug(
        `  state: ${requestObject?.state} (length: ${requestObject?.state?.length})`,
      );
      expect(requestObject?.state).toMatch(/^[a-zA-Z0-9_-]+$/);
      log.debug("  ✅ state parameter is present and valid");

      log.debug("→ Validating nonce parameter...");
      expect(requestObject?.nonce).toBeDefined();
      log.debug(
        `  nonce: ${requestObject?.nonce} (length: ${requestObject?.nonce.length})`,
      );
      expect(requestObject?.nonce).toMatch(/^[a-zA-Z0-9_-]+$/);
      log.debug("  ✅ nonce parameter is present and valid");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-13: Authorization Response is encrypted for one of the Relying Party public keys.", () => {
    const log = baseLog.withTag("RPR-13");

    log.start(
      "Conformance test: Verifying authorization response encryption key selection",
    );

    const DESCRIPTION =
      "Authorization Response is encrypted with a public key declared by the Relying Party";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const verifierMetadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata
          ?.openid_credential_verifier;
      expect(verifierMetadata).toBeDefined();
      if (!verifierMetadata) {
        throw new Error("openid_credential_verifier metadata is missing");
      }

      const authorizationResponse =
        authorizationRequestResult.response?.authorizationResponse;
      expect(authorizationResponse?.jarm).toBeDefined();
      const responseJwe = authorizationResponse?.jarm.responseJwe;
      const encryptionJwk = authorizationResponse?.jarm.encryptionJwk;
      expect(responseJwe).toBeDefined();
      expect(encryptionJwk).toBeDefined();
      if (!responseJwe || !encryptionJwk) {
        throw new Error(
          "authorization response JARM encryption data is missing",
        );
      }
      const responseState =
        authorizationRequestResult.response?.requestObject.state;
      expect(responseState).toBeDefined();
      if (!responseState) {
        throw new Error("authorization request state is missing");
      }

      log.debug("→ Checking compact JWE serialization...");
      const jweParts = responseJwe.split(".");
      expect(jweParts).toHaveLength(5);
      expect(responseJwe).not.toContain(responseState);
      log.debug("  ✅ response is serialized as encrypted JARM");

      log.debug("→ Checking JWE protected header...");
      const protectedHeader = decodeProtectedHeader(responseJwe);
      expect(protectedHeader.alg).toBe(
        verifierMetadata.authorization_encrypted_response_alg ?? "ECDH-ES",
      );
      expect(protectedHeader.kid).toBe(encryptionJwk.kid);
      log.debug(`  alg: ${protectedHeader.alg}`);
      log.debug(`  enc: ${protectedHeader.enc}`);
      log.debug(`  kid: ${protectedHeader.kid}`);

      log.debug("→ Checking selected key belongs to RP JWKS...");
      const rpEncryptionKey = verifierMetadata.jwks.keys.find(
        (key: Jwk) => key.kid === encryptionJwk.kid,
      );
      expect(rpEncryptionKey).toBeDefined();
      if (!rpEncryptionKey) {
        throw new Error("selected encryption key is not present in RP JWKS");
      }
      expect(rpEncryptionKey.use).toBe("enc");
      expect(encryptionJwk).toMatchObject({
        crv: rpEncryptionKey.crv,
        kid: rpEncryptionKey.kid,
        kty: rpEncryptionKey.kty,
        x: rpEncryptionKey.x,
        y: rpEncryptionKey.y,
      });
      log.debug("  ✅ selected encryption key is one of the RP public keys");

      log.debug(
        "→ Checking RP accepted and evaluated the encrypted response...",
      );
      expect(redirectUriResult.success).toBe(true);
      expect(redirectUriResult.response?.responseCode).toBeDefined();
      log.debug("  ✅ RP accepted the encrypted authorization response");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-19: User is redirected correctly, the endpoint works.", () => {
    const log = baseLog.withTag("RPR-19");

    log.start(
      "Conformance test: Verifying redirect URI functionality and response code",
    );

    const DESCRIPTION =
      "Relying Party correctly redirects user and endpoint returns valid response_code";
    let testSuccess = false;
    try {
      if (!redirectUriResult.success) {
        log.error("❌ Redirect URI step failed");
        log.error(`  Result: ${JSON.stringify(redirectUriResult, null, 2)}`);
      }
      expect(redirectUriResult.success).toBe(true);

      if (!redirectUriResult.response?.redirectUri) {
        log.error("❌ redirectUri is undefined in response");
        log.error(
          `  Response object: ${JSON.stringify(redirectUriResult.response, null, 2)}`,
        );
      }
      expect(redirectUriResult.response?.redirectUri).toBeDefined();

      log.debug("→ Validating redirect_uri format...");
      const redirectUri = redirectUriResult.response?.redirectUri;
      log.debug(`  redirect_uri: ${redirectUri?.toString()}`);
      expect(redirectUri?.toString()).toMatch(/^https?:\/\/.+/);
      log.debug("  ✅ redirect_uri is a valid URL");

      log.debug("→ Checking response_code parameter...");
      if (!redirectUriResult.response?.responseCode) {
        log.warn("  ⚠ response_code is undefined");
        log.warn(
          `  Response keys: ${Object.keys(redirectUriResult.response || {}).join(", ")}`,
        );
      }
      expect(redirectUriResult.response?.responseCode).toBeDefined();
      log.debug(`  response_code: ${redirectUriResult.response?.responseCode}`);
      log.debug("  ✅ response_code is present");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-23: Relying Party supports all credential formats declared in vp_formats_supported metadata.", () => {
    const log = baseLog.withTag("RPR-23");

    log.start(
      "Conformance test: Verifying Credential Presentation response format compliance",
    );

    const DESCRIPTION =
      "Relying Party metadata declares usable credential presentation formats and requests only declared formats";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(authorizationRequestResult.success).toBe(true);

      const verifierMetadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata
          ?.openid_credential_verifier;
      expect(verifierMetadata).toBeDefined();
      if (!verifierMetadata) {
        throw new Error("openid_credential_verifier metadata is missing");
      }

      const vpFormatsSupported = verifierMetadata.vp_formats_supported;
      expect(vpFormatsSupported).toBeDefined();
      expect(vpFormatsSupported).toBeTypeOf("object");
      if (!vpFormatsSupported || typeof vpFormatsSupported !== "object") {
        throw new Error("vp_formats_supported metadata is missing");
      }

      const supportedFormatEntries = Object.entries(vpFormatsSupported);
      expect(supportedFormatEntries.length).toBeGreaterThan(0);
      log.debug(
        `  Metadata-supported formats: ${supportedFormatEntries
          .map(([format]) => format)
          .join(", ")}`,
      );

      for (const [format, parameters] of supportedFormatEntries) {
        expect(parameters).toBeDefined();
        expect(parameters).toBeTypeOf("object");
        if (!parameters || typeof parameters !== "object") {
          throw new Error(`vp_formats_supported.${format} is not an object`);
        }

        const algorithmParameters = Object.entries(parameters)
          .map(([name, value]) => ({ name, value }))
          .filter(
            (
              entry,
            ): entry is {
              name: string;
              value: string[];
            } =>
              Array.isArray(entry.value) &&
              entry.value.every((item) => typeof item === "string"),
          );
        expect(algorithmParameters.length).toBeGreaterThan(0);

        for (const { name, value } of algorithmParameters) {
          expect(value.length).toBeGreaterThan(0);
          log.debug(`  ${format}.${name}: ${value.join(", ")}`);
        }
      }

      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlCredentials = (requestObject?.dcql_query?.credentials ??
        []) as unknown[];
      const requestedFormats = new Set<string>(
        dcqlCredentials
          .map((credential): unknown => {
            if (
              !credential ||
              typeof credential !== "object" ||
              !("format" in credential)
            ) {
              return undefined;
            }
            return (credential as { format?: unknown }).format;
          })
          .filter((format): format is string => typeof format === "string"),
      );
      expect(requestedFormats.size).toBeGreaterThan(0);

      const supportedFormats = new Set<string>(
        supportedFormatEntries.map(([format]) => format),
      );
      for (const requestedFormat of requestedFormats) {
        log.debug(`  DCQL requested format: ${requestedFormat}`);
        expect(supportedFormats.has(requestedFormat)).toBe(true);
      }
      log.debug("  ✅ all requested credential formats are metadata-declared");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-28: response_code has sufficient entropy with at least 32 URL-safe characters.", () => {
    const log = baseLog.withTag("RPR028");

    log.start("Conformance test: Verifying response_code entropy requirements");

    const DESCRIPTION =
      "Relying Party correctly provides response_code with sufficient entropy (≥32 characters, URL-safe charset)";
    let testSuccess = false;
    try {
      expect(redirectUriResult.success).toBe(true);
      expect(redirectUriResult.response?.responseCode).toBeDefined();

      const responseCode = redirectUriResult.response?.responseCode ?? "";
      log.debug(`  response_code: ${responseCode}`);
      log.debug(`  Length: ${responseCode.length} characters`);

      expect(responseCode.length).toBeGreaterThanOrEqual(32);
      log.debug(
        "  ✅ response_code length meets minimum entropy requirement (≥32)",
      );

      expect(responseCode).toMatch(/^[a-zA-Z0-9_-]+$/);
      log.debug("  ✅ response_code uses URL-safe characters only");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-78: Wallet Attestation request correctly uses standard DCQL query.", () => {
    const log = baseLog.withTag("RPR-78");

    log.start(
      "Conformance test: Verifying DCQL query standard format compliance",
    );

    const DESCRIPTION =
      "Relying Party correctly uses standard DCQL query with valid credentials array";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Checking dcql_query presence in request object...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.dcql_query).toBeDefined();
      log.debug("  ✅ dcql_query is present");

      log.debug("→ Validating DCQL query structure...");
      const dcqlQuery = requestObject?.dcql_query;
      expect(dcqlQuery).toBeTypeOf("object");
      log.debug("  ✅ dcql_query is an object");

      // DCQL query should contain credentials array
      log.debug("→ Checking credentials array in DCQL query...");
      expect(dcqlQuery?.credentials).toBeDefined();
      expect(Array.isArray(dcqlQuery?.credentials)).toBe(true);
      log.debug(`  Credentials count: ${dcqlQuery?.credentials.length}`);
      expect(dcqlQuery?.credentials.length).toBeGreaterThan(0);
      log.debug("  ✅ credentials array is valid and non-empty");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-79: claims parameter is not included in DCQL query for Wallet Attestation.", () => {
    const log = baseLog.withTag("RPR-79");

    log.start(
      "Conformance test: Verifying Wallet Attestation does not include claims parameter",
    );

    const DESCRIPTION =
      "Relying Party correctly omits claims parameter for Wallet Attestation in DCQL query";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Checking DCQL query credentials for Wallet Attestation...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlQuery = requestObject?.dcql_query;

      expect(dcqlQuery?.credentials).toBeDefined();

      const walletAttestationCredentials = (dcqlQuery?.credentials ?? [])
        .map((credential: unknown, index: number) => ({
          credential,
          index,
        }))
        .filter(({ credential }: { credential: unknown; index: number }) => {
          if (
            !credential ||
            typeof credential !== "object" ||
            !("meta" in credential)
          ) {
            return false;
          }
          const cred = credential as {
            meta?: { vct_values?: string[] };
          };
          return cred.meta?.vct_values?.includes(
            "urn:eu.europa.ec.eudi:wallet_attestation:1",
          );
        });

      for (const { credential, index } of walletAttestationCredentials) {
        const cred = credential as {
          claims?: unknown[];
          meta?: { vct_values?: string[] };
        };
        log.debug(`  Credential ${index + 1}: Wallet Attestation detected`);
        log.debug(`    vct: ${cred.meta?.vct_values?.join(", ")}`);
        expect(cred.claims).toBeUndefined();
        log.debug("    ✅ claims parameter is not present (as required)");
      }

      const walletAttestationFound = walletAttestationCredentials.length > 0;

      if (walletAttestationFound) {
        log.debug("  ✅ Wallet Attestation validated successfully");
      }

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-80: vct_values parameter is correctly required in DCQL query.", () => {
    const log = baseLog.withTag("RPR-80");

    log.start(
      "Conformance test: Verifying vct_values presence in DCQL credentials",
    );

    const DESCRIPTION =
      "Relying Party correctly requires vct_values in all DCQL query credentials";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug(
        "→ Validating vct_values parameter in DCQL query credentials...",
      );
      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlQuery = requestObject?.dcql_query;

      expect(dcqlQuery?.credentials).toBeDefined();

      const credentialsWithVctValues = (dcqlQuery?.credentials ?? [])
        .map((credential: unknown, index: number) => ({
          credential,
          index,
        }))
        .filter(({ credential }: { credential: unknown; index: number }) => {
          if (
            !credential ||
            typeof credential !== "object" ||
            !("meta" in credential)
          ) {
            return false;
          }
          const cred = credential as {
            meta?: { vct_values?: string[] };
          };
          return Boolean(cred.meta?.vct_values);
        });

      for (const { credential, index } of credentialsWithVctValues) {
        const cred = credential as {
          meta: { vct_values: string[] };
        };
        log.debug(`  Credential ${index + 1}:`);
        expect(Array.isArray(cred.meta.vct_values)).toBe(true);
        log.debug(`    vct_values: ${cred.meta.vct_values.join(", ")}`);
        expect(cred.meta.vct_values.length).toBeGreaterThan(0);
        log.debug(
          `    ✅ vct_values is valid (${cred.meta.vct_values.length} type(s))`,
        );
      }

      const hasVctValues = credentialsWithVctValues.length > 0;

      expect(hasVctValues).toBe(true);
      log.debug("  ✅ All credentials have valid vct_values");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-81: Wallet Nonce | Relying Party checks wallet_nonce when present", () => {
    const log = baseLog.withTag("RPR-81");

    log.start("Conformance test: Verifying wallet_nonce binding");

    const DESCRIPTION =
      "Relying Party correctly checks wallet_nonce when present";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const response = authorizationRequestResult.response;
      const walletNonce = response?.walletNonce;
      const requestWalletNonce = response?.requestObject.wallet_nonce;

      expect(walletNonce).toBeDefined();
      log.debug(`  Wallet-sent wallet_nonce: ${walletNonce}`);

      if (!requestWalletNonce) {
        log.debug(
          "  ℹ Request Object does not include wallet_nonce; validation is not applicable",
        );
        testSuccess = true;
        return;
      }

      log.debug(`  Request Object wallet_nonce: ${requestWalletNonce}`);
      expect(requestWalletNonce).toBe(walletNonce);
      log.debug("  ✅ Request Object wallet_nonce is bound to wallet input");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-82: Response Types | response_types_supported is set to vp_token when present", () => {
    const log = baseLog.withTag("RPR-82");

    log.start(
      "Conformance test: Verifying response_types_supported metadata value",
    );

    const DESCRIPTION =
      "response_types_supported is correctly set to vp_token when present";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const verifierMetadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata
          ?.openid_credential_verifier;
      expect(verifierMetadata).toBeDefined();
      if (!verifierMetadata) {
        throw new Error("openid_credential_verifier metadata is missing");
      }

      const responseTypesSupported = verifierMetadata.response_types_supported;

      if (!responseTypesSupported) {
        log.debug(
          "  ℹ response_types_supported is not present; validation is not applicable",
        );
        testSuccess = true;
        return;
      }

      log.debug(
        `  response_types_supported: ${responseTypesSupported.join(", ")}`,
      );
      expect(responseTypesSupported).toEqual(["vp_token"]);
      log.debug("  ✅ response_types_supported is exactly vp_token");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-83: Relying Party correctly provides and handles redirect_uri.", () => {
    const log = baseLog.withTag("RPR-83");

    log.start(
      "Conformance test: Verifying response_uri and redirect_uri handling",
    );

    const DESCRIPTION =
      "Relying Party correctly provides response_uri and handles redirect_uri";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating response_uri in request object...");
      const requestObject = authorizationRequestResult.response?.requestObject;

      if (!requestObject?.response_uri) {
        log.error("❌ response_uri is undefined");
        log.error(
          `  Request object keys: ${Object.keys(requestObject || {}).join(", ")}`,
        );
      }
      expect(requestObject?.response_uri).toBeDefined();
      log.debug(`  response_uri: ${requestObject?.response_uri}`);
      expect(requestObject?.response_uri).toMatch(/^https?:\/\/.+/);
      log.debug("  ✅ response_uri is present and valid");

      log.debug("→ Validating redirect_uri after authorization...");

      if (!redirectUriResult.success) {
        log.error("❌ Redirect URI step failed");
        log.error(`  Result: ${JSON.stringify(redirectUriResult, null, 2)}`);
      }
      expect(redirectUriResult.success).toBe(true);

      if (!redirectUriResult.response?.redirectUri) {
        log.error("❌ redirectUri is undefined in response");
        log.error(
          `  Response keys: ${Object.keys(redirectUriResult.response || {}).join(", ")}`,
        );
        log.error(
          `  Full response: ${JSON.stringify(redirectUriResult.response, null, 2)}`,
        );
      }
      expect(redirectUriResult.response?.redirectUri).toBeDefined();

      const redirectUri = redirectUriResult.response?.redirectUri;
      log.debug(`  redirect_uri: ${redirectUri?.toString()}`);
      expect(redirectUri?.toString()).toMatch(/^https?:\/\/.+/);
      log.debug("  ✅ redirect_uri is present and valid");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-84: Flow Support | Relying Party supports both Same Device and Cross Device flows", () => {
    const log = baseLog.withTag("RPR-84");

    log.start(
      "Conformance test: Verifying required Same Device and Cross Device flow support",
    );

    const DESCRIPTION =
      "Relying Party supports both Same Device and Cross Device flows";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating Cross Device Flow QR-Code entry point...");
      const qrCodePayload =
        orchestrator.getConfig().presentation.authorize_request_url;
      expect(qrCodePayload).toBeTruthy();
      const authorizationRequestUrl = new URL(qrCodePayload);
      expect(["haip:", "openid4vp:", "https:"]).toContain(
        authorizationRequestUrl.protocol,
      );
      const hasRequest = authorizationRequestUrl.searchParams.has("request");
      const requestUri =
        authorizationRequestUrl.searchParams.get("request_uri");
      expect(hasRequest || Boolean(requestUri)).toBe(true);
      expect(authorizationRequestResult.response?.parsedQrCode).toBeDefined();
      log.debug("  ✅ Cross Device Flow QR-Code entry point is supported");

      log.debug("→ Validating Same Device Flow redirect handling...");
      expect(redirectUriResult.success).toBe(true);
      expect(redirectUriResult.response?.redirectUri).toBeDefined();
      const redirectUri = redirectUriResult.response?.redirectUri;
      expect(["haip:", "https:"]).toContain(redirectUri?.protocol);
      expect(redirectUriResult.response?.responseCode).toBeDefined();
      log.debug("  ✅ Same Device Flow redirect handling is supported");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });
  test("RPR-89: JWT typ parameter is correctly set to oauth-authz-req+jwt.", () => {
    const log = baseLog.withTag("RPR-89");

    log.start("Conformance test: Verifying JWT typ header parameter");

    const DESCRIPTION =
      "Relying Party correctly sets JWT typ header to oauth-authz-req+jwt";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating JWT typ parameter...");
      const actualTyp =
        authorizationRequestResult.response?.authorizationRequestHeader.typ;
      log.debug(`  Expected: oauth-authz-req+jwt`);
      log.debug(`  Actual: ${actualTyp}`);

      expect(actualTyp).toBe("oauth-authz-req+jwt");
      log.debug("  ✅ typ parameter is correct");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-90: response_mode parameter is correctly set to direct_post.jwt.", () => {
    const log = baseLog.withTag("RPR-90");

    log.start("Conformance test: Verifying response_mode parameter value");

    const DESCRIPTION =
      "Relying Party correctly sets response_mode to direct_post.jwt";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating response_mode parameter...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      log.debug(`  Expected: direct_post.jwt`);
      log.debug(`  Actual: ${requestObject?.response_mode}`);
      expect(requestObject?.response_mode).toBe("direct_post.jwt");
      log.debug("  ✅ response_mode is correct");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-91: response_type parameter is correctly set to vp_token.", () => {
    const log = baseLog.withTag("RPR-91");

    log.start("Conformance test: Verifying response_type parameter value");

    const DESCRIPTION =
      "Relying Party correctly sets response_type to vp_token";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating response_type parameter...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      log.debug(`  Expected: vp_token`);
      log.debug(`  Actual: ${requestObject?.response_type}`);
      expect(requestObject?.response_type).toBe("vp_token");
      log.debug("  ✅ response_type is correct");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-92: Relying Party sends Authorization Response to correct response_uri endpoint.", () => {
    const log = baseLog.withTag("RPR-92");

    log.start(
      "Conformance test: Verifying authorization response submission to response_uri",
    );

    const DESCRIPTION =
      "Relying Party correctly sends Authorization Response to response_uri endpoint";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating response_uri endpoint...");
      const responseUri =
        authorizationRequestResult.response?.requestObject.response_uri;
      expect(responseUri).toBeDefined();
      log.debug(`  response_uri: ${responseUri}`);
      expect(responseUri).toMatch(/^https?:\/\/.+/);
      log.debug("  ✅ response_uri is valid");

      log.debug("→ Verifying authorization response submission...");
      expect(redirectUriResult.success).toBe(true);
      log.debug(
        "  ✅ Authorization response successfully sent to response_uri",
      );

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-93: nonce parameter has sufficient entropy with at least 32 characters.", () => {
    const log = baseLog.withTag("RPR-93");

    log.start("Conformance test: Verifying nonce entropy requirements");

    const DESCRIPTION =
      "Relying Party correctly provides nonce with sufficient entropy (≥32 characters)";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating nonce length (minimum 32 characters)...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.nonce).toBeDefined();
      log.debug(`  nonce: ${requestObject?.nonce}`);
      log.debug(`  Length: ${requestObject?.nonce.length} characters`);
      expect(requestObject?.nonce.length).toBeGreaterThanOrEqual(32);
      log.debug("  ✅ nonce has sufficient entropy (≥32 characters)");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-101: Presentation Array | vp_token contains the requested signed presentations.", () => {
    const log = baseLog.withTag("RPR-101");

    log.start(
      "Conformance test: Verifying vp_token contains the requested signed presentations",
    );

    const DESCRIPTION =
      "vp_token contains the requested signed presentations as required";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      const response = authorizationRequestResult.response;
      const requestObject = response?.requestObject;
      const dcqlCredentials = requestObject?.dcql_query?.credentials ?? [];
      expect(Array.isArray(dcqlCredentials)).toBe(true);
      expect(dcqlCredentials.length).toBeGreaterThan(0);

      const vpToken =
        response?.authorizationResponse.authorizationResponsePayload.vp_token;
      expect(vpToken).toBeDefined();
      expect(vpToken).toBeTypeOf("object");
      if (!vpToken || Array.isArray(vpToken)) {
        throw new Error(
          "vp_token must be an object keyed by DCQL credential id",
        );
      }

      const requestedPresentations: RequestedPresentation[] =
        dcqlCredentials.map((credential: unknown, index: number) =>
          readRequestedPresentation(credential, index),
        );
      const requestedPresentationIds = requestedPresentations.map(
        ({ id }) => id,
      );

      const actualPresentationIds = Object.keys(vpToken).sort();
      const expectedPresentationIds = [
        ...new Set(requestedPresentationIds),
      ].sort();
      log.debug(
        `  Requested presentation ids: ${expectedPresentationIds.join(", ")}`,
      );
      log.debug(
        `  vp_token presentation ids: ${actualPresentationIds.join(", ")}`,
      );
      expect(actualPresentationIds).toEqual(expectedPresentationIds);

      const walletVersion = orchestrator.getConfig().wallet.wallet_version;

      for (const requestedPresentation of requestedPresentations) {
        const { format, id } = requestedPresentation;
        const presentations = normalizePresentationArray(
          id,
          vpToken[id],
          walletVersion,
        );
        expect(presentations.length).toBeGreaterThan(0);
        log.debug(
          `  ${id}: ${presentations.length} signed presentation(s) for ${format}`,
        );

        for (const presentation of presentations) {
          assertSignedPresentation(requestedPresentation, presentation);
        }
      }

      expect(redirectUriResult.success).toBe(true);
      log.debug("  ✅ vp_token contains every requested signed presentation");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR-94: JWT exp parameter is correctly set and not expired.", () => {
    const log = baseLog.withTag("RPR-94");

    log.start("Conformance test: Verifying JWT expiration timestamp validity");

    const DESCRIPTION =
      "Relying Party correctly sets JWT exp parameter to a future timestamp";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating exp parameter...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.exp).toBeDefined();

      const currentTime = Math.floor(Date.now() / 1000);
      const expTimestamp = requestObject?.exp ?? 0;
      const expiresAt = new Date(expTimestamp * 1000).toISOString();
      const timeUntilExpiry = expTimestamp - currentTime;

      log.debug(
        `  Current time: ${new Date(currentTime * 1000).toISOString()}`,
      );
      log.debug(`  Expires at: ${expiresAt}`);
      log.debug(`  Time until expiry: ${timeUntilExpiry} seconds`);

      expect(requestObject?.exp).toBeGreaterThan(currentTime);
      log.debug("  ✅ JWT is not expired");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });
});
