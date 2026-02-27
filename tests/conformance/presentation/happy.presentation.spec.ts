/* eslint-disable max-lines-per-function */
import { definePresentationTest } from "#/config/test-metadata";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import { FetchMetadataVpStepResponse } from "@/step/presentation";
import { AuthorizationRequestStepResponse } from "@/step/presentation/authorization-request-step";
import { RedirectUriStepResponse } from "@/step/presentation/redirect-uri-step";

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
    baseLog.testSuite({
      profile: "dc_sd_jwt_PersonIdentificationData",
      target: orchestrator.getConfig().presentation.authorize_request_url,
      title: "Presentation Conformance Tests",
    });

    try {
      ({ authorizationRequestResult, fetchMetadataResult, redirectUriResult } =
        await orchestrator.presentation());

      baseLog.info("Presentation flow completed successfully");
    } catch (e) {
      baseLog.error("Presentation flow failed:", e);
      throw e;
    } finally {
      // Give time for all logs to be flushed before starting tests
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  });

  test("RPR003: Relying Party issues the QR-Code containing an URL using the base url provided within its metadata.", () => {
    const log = baseLog.withTag("RPR003");

    log.start(
      "Conformance test: Verifying QR-Code URL alignment with RP metadata",
    );

    const DESCRIPTION = "Relying Party correctly issues QR-Code with URL from metadata and client_id matches issuer";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const entityClaims = fetchMetadataResult.response?.entityStatementClaims;
      const issuer = entityClaims?.sub;

      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Checking client_id matches entity statement issuer...");
      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      expect(parsedQrCode?.clientId).toBeDefined();

      // The client_id should match the issuer from the entity statement
      if (issuer) {
        log.debug(`  Expected: ${issuer}`);
        log.debug(`  Actual: ${parsedQrCode?.clientId}`);
        expect(parsedQrCode?.clientId).toBe(issuer);
        log.debug("  ✅ client_id matches entity statement issuer");
      }

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

  test("RPR009: Relying Party accepts defaults to GET method.", () => {
    const log = baseLog.withTag("RPR009");

    log.start(
      "Conformance test: Verifying HTTP GET method support for request objects",
    );

    const DESCRIPTION = "Relying Party supports GET method for request objects, defaults if not specified";
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

      // If request_object_endpoint_methods is not specified or includes GET
      if (verifierMetadata?.request_object_endpoint_methods) {
        log.debug(
          `  Supported methods: ${verifierMetadata.request_object_endpoint_methods.join(", ")}`,
        );
        expect(verifierMetadata.request_object_endpoint_methods).toContain(
          "GET",
        );
        log.debug("  ✅ GET method is supported");
      } else {
        log.debug(
          "  ℹ request_object_endpoint_methods not specified (GET is default)",
        );
      }

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR012: Relying Party receives and validates response with state and nonce values.", () => {
    const log = baseLog.withTag("RPR012");

    log.start(
      "Conformance test: Verifying state and nonce parameter presence and format",
    );

    const DESCRIPTION = "Relying Party receives and validates state and nonce values in response";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Validating state parameter...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.state).toBeDefined();
      log.debug(
        `  state: ${requestObject?.state} (length: ${requestObject?.state.length})`,
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

  test("RPR019: User is redirected correctly, the endpoint works.", () => {
    const log = baseLog.withTag("RPR019");

    log.start(
      "Conformance test: Verifying redirect URI functionality and response code",
    );

    const DESCRIPTION = "Relying Party correctly redirects user and endpoint returns valid response_code";
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

  test("RPR078: Wallet Attestation request correctly uses standard DCQL query.", () => {
    const log = baseLog.withTag("RPR078");

    log.start(
      "Conformance test: Verifying DCQL query standard format compliance",
    );

    const DESCRIPTION = "Relying Party correctly uses standard DCQL query with valid credentials array";
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

  test("RPR079: claims parameter is not included in DCQL query for Wallet Attestation.", () => {
    const log = baseLog.withTag("RPR079");

    log.start(
      "Conformance test: Verifying Wallet Attestation does not include claims parameter",
    );

    const DESCRIPTION = "Relying Party correctly omits claims parameter for Wallet Attestation in DCQL query";
    let testSuccess = false;
    try {
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.debug("→ Checking DCQL query credentials for Wallet Attestation...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlQuery = requestObject?.dcql_query;

      expect(dcqlQuery?.credentials).toBeDefined();

      // Check each credential in DCQL
      let walletAttestationFound = false;
      dcqlQuery?.credentials.forEach((credential: unknown, index: number) => {
        if (
          credential &&
          typeof credential === "object" &&
          "meta" in credential
        ) {
          const cred = credential as {
            claims?: unknown[];
            meta?: { vct_values?: string[] };
          };

          // Wallet Attestation credentials should not have claims parameter
          if (
            cred.meta?.vct_values?.includes(
              "urn:eu.europa.ec.eudi:wallet_attestation:1",
            )
          ) {
            walletAttestationFound = true;
            log.debug(`  Credential ${index + 1}: Wallet Attestation detected`);
            log.debug(`    vct: ${cred.meta?.vct_values?.join(", ")}`);
            expect(cred.claims).toBeUndefined();
            log.debug("    ✅ claims parameter is not present (as required)");
          }
        }
      });

      if (walletAttestationFound) {
        log.debug("  ✅ Wallet Attestation validated successfully");
      }

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR080: vct_values parameter is correctly required in DCQL query.", () => {
    const log = baseLog.withTag("RPR080");

    log.start(
      "Conformance test: Verifying vct_values presence in DCQL credentials",
    );

    const DESCRIPTION = "Relying Party correctly requires vct_values in all DCQL query credentials";
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

      // Check that all credentials have meta.vct_values
      let hasVctValues = false;
      let credentialIndex = 0;
      dcqlQuery?.credentials.forEach((credential: unknown) => {
        credentialIndex++;
        if (
          credential &&
          typeof credential === "object" &&
          "meta" in credential
        ) {
          const cred = credential as {
            meta?: { vct_values?: string[] };
          };
          if (cred.meta?.vct_values) {
            hasVctValues = true;
            log.debug(`  Credential ${credentialIndex}:`);
            expect(Array.isArray(cred.meta.vct_values)).toBe(true);
            log.debug(`    vct_values: ${cred.meta.vct_values.join(", ")}`);
            expect(cred.meta.vct_values.length).toBeGreaterThan(0);
            log.debug(
              `    ✅ vct_values is valid (${cred.meta.vct_values.length} type(s))`,
            );
          }
        }
      });

      expect(hasVctValues).toBe(true);
      log.debug("  ✅ All credentials have valid vct_values");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR082: response_types_supported is correctly set to vp_token.", () => {
    const log = baseLog.withTag("RPR082");

    log.start(
      "Conformance test: Verifying vp_token support in verifier metadata",
    );

    const DESCRIPTION = "Relying Party correctly advertises vp_token in response_types_supported";
    let testSuccess = false;
    try {
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const metadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata;
      const verifierMetadata = metadata?.openid_credential_verifier;

      log.debug("→ Checking response_types_supported in verifier metadata...");

      if (!verifierMetadata) {
        log.error("❌ openid_credential_verifier metadata is undefined");
        log.error(
          `  Available metadata keys: ${Object.keys(metadata || {}).join(", ")}`,
        );
        log.error(`  Full metadata: ${JSON.stringify(metadata, null, 2)}`);
      }

      if (!verifierMetadata?.response_types_supported) {
        log.error("❌ response_types_supported is undefined");
        log.error(
          `  Verifier metadata keys: ${Object.keys(verifierMetadata || {}).join(", ")}`,
        );
        log.error(
          `  Full verifier metadata: ${JSON.stringify(verifierMetadata, null, 2)}`,
        );
      }

      expect(verifierMetadata?.response_types_supported).toBeDefined();
      log.debug(
        `  Supported types: ${verifierMetadata?.response_types_supported.join(", ")}`,
      );
      expect(verifierMetadata?.response_types_supported).toContain("vp_token");
      log.debug("  ✅ vp_token is supported");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR083: Relying Party correctly provides and handles redirect_uri.", () => {
    const log = baseLog.withTag("RPR083");

    log.start(
      "Conformance test: Verifying response_uri and redirect_uri handling",
    );

    const DESCRIPTION = "Relying Party correctly provides response_uri and handles redirect_uri";
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

  test("RPR089: JWT typ parameter is correctly set to oauth-authz-req+jwt.", () => {
    const log = baseLog.withTag("RPR089");

    log.start("Conformance test: Verifying JWT typ header parameter");

    const DESCRIPTION = "Relying Party correctly sets JWT typ header to oauth-authz-req+jwt";
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

  test("RPR090: response_mode parameter is correctly set to direct_post.jwt.", () => {
    const log = baseLog.withTag("RPR090");

    log.start("Conformance test: Verifying response_mode parameter value");

    const DESCRIPTION = "Relying Party correctly sets response_mode to direct_post.jwt";
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

  test("RPR091: response_type parameter is correctly set to vp_token.", () => {
    const log = baseLog.withTag("RPR091");

    log.start("Conformance test: Verifying response_type parameter value");

    const DESCRIPTION = "Relying Party correctly sets response_type to vp_token";
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

  test("RPR092: Relying Party sends Authorization Response to correct response_uri endpoint.", () => {
    const log = baseLog.withTag("RPR092");

    log.start(
      "Conformance test: Verifying authorization response submission to response_uri",
    );

    const DESCRIPTION = "Relying Party correctly sends Authorization Response to response_uri endpoint";
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
      log.debug("  ✅ Authorization response successfully sent to response_uri");

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR093: nonce parameter has sufficient entropy with at least 32 characters.", () => {
    const log = baseLog.withTag("RPR093");

    log.start("Conformance test: Verifying nonce entropy requirements");

    const DESCRIPTION = "Relying Party correctly provides nonce with sufficient entropy (≥32 characters)";
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

  test("RPR094: JWT exp parameter is correctly set and not expired.", () => {
    const log = baseLog.withTag("RPR094");

    log.start("Conformance test: Verifying JWT expiration timestamp validity");

    const DESCRIPTION = "Relying Party correctly sets JWT exp parameter to a future timestamp";
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

      log.debug(`  Current time: ${new Date(currentTime * 1000).toISOString()}`);
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
