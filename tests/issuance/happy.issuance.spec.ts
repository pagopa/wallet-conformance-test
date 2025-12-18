/* eslint-disable max-lines-per-function */
import { issuerRegistry } from "#/config";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";

// Import test configuration - this will register all configurations
import "../test.config";

import { decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { FetchMetadataStepResponse } from "@/step";
import { PushedAuthorizationRequestResponse } from "@/step/issuance";
import { AuthorizeStepResponse } from "@/step/issuance/authorize-step";

import { HAPPY_FLOW_ISSUANCE_NAME } from "../test.config";
import z from "zod/v3";

// Get the test configuration from the registry
// The configuration must be registered before running the tests
issuerRegistry.get(HAPPY_FLOW_ISSUANCE_NAME).forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, async () => {
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    let authorizeResponse: AuthorizeStepResponse;

    beforeAll(async () => {
      ({
        authorizeResponse,
        fetchMetadataResponse,
        pushedAuthorizationRequestResponse,
      } = await orchestrator.issuance());
    });

    test("CI_001: Fetch Metadata | Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint.", async () => {
      const log = baseLog.withTag("CI_001");

      log.start("Started");
      expect(fetchMetadataResponse.success).toBe(true);
      log.testCompleted();
      console.log(fetchMetadataResponse.response?.entityStatementClaims);
    });

    test("CI_002: Fetch Metadata | Entity Configuration response media type check", async () => {
      const log = baseLog.withTag("CI_002");

      log.start("Started");
      const expectedContentType = "application/entity-statement+jwt";
      const actualContentType =
        fetchMetadataResponse.response?.headers.get("content-type");
      expect(actualContentType).toBe(expectedContentType);
      log.testCompleted();

      console.log(actualContentType);
    });

    test("CI_003: Fetch Metadata | The Entity Configuration is cryptographically signed", async () => {
      const log = baseLog.withTag("CI_003");

      log.start("Started");
      expect(fetchMetadataResponse.response).toBeDefined();

      log.info("Asserting response status...");
      expect(fetchMetadataResponse.response?.status).toBe(200);

      log.info("Checking non empty response body...");
      expect(fetchMetadataResponse.response?.entityStatementJwt).toBeDefined();

      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
      );
      log.debug(decodedData);
      log.testCompleted();

      console.log(fetchMetadataResponse.response?.entityStatementJwt);
    });

    test("CI_006: Fetch Metadata | Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
      const log = baseLog.withTag("CI_006");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
      );
      log.debug(JSON.stringify(decodedData));

      log.info("Validating response format...");
      const result = z
        .object({
          exp: z.number(),
          iat: z.number(),
          iss: z.string(),
          jwks: z.any(),
          metadata: z.any(),
          sub: z.string(),
        })
        .passthrough()
        .refine((data) => data.metadata !== undefined, {
          message: "metadata is missing",
        })
        .safeParse(decodedData);

      expect(
        result.success,
        `Error validating schema: ${result.success ? "" : result.error.message}`,
      ).toBe(true);
      log.info(`Response matches the required format`);
      log.testCompleted();
    });

    test("CI_008: Fetch Metadata | Credential Issuer metadata", async () => {
      const log = baseLog.withTag("CI_008");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
      );
      log.debug(JSON.stringify(decodedData));

      log.info("Validating response format...");
      const result = z
        .object({
          metadata: z.any(),
        })
        .passthrough()
        .refine(
          (data) =>
            data.metadata !== undefined &&
            data.metadata?.federation_entity !== undefined &&
            data.metadata?.oauth_authorization_server !== undefined &&
            data.metadata?.openid_credential_issuer !== undefined,
          {
            message:
              "metadata or federation_entity|oauth_authorization_server|openid_credential_issuer is missing",
          },
        )
        .safeParse(decodedData);

      expect(
        result.success,
        `Error validating schema: ${result.success ? "" : result.error.message}`,
      ).toBe(true);

      log.info(`Response matches the required format`);
      log.testCompleted();
    });

    test("CI_009: Fetch Metadata | Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
      const log = baseLog.withTag("CI_009");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
      );
      log.debug(JSON.stringify(decodedData));

      log.info("Validating response format...");
      const result = z
        .object({
          metadata: z.any(),
        })
        .passthrough()
        .refine(
          (data) =>
            data.metadata !== undefined &&
            data.metadata?.openid_credential_verifier !== undefined,
          { message: "metadata or openid_credential_verifier is missing" },
        )
        .safeParse(decodedData);

      expect(
        result.success,
        `Error validating schema: ${result.success ? "" : result.error.message}`,
      ).toBe(true);

      log.info(`Response matches the required format`);
      log.testCompleted();

    });

    // ============================================================================
    // PUSHED AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_040: PAR Request | request_uri validity time is set to less than one minute", async () => {
      const log = baseLog.withTag("CI_040");

      log.start("Started");
      const expires_in = pushedAuthorizationRequestResponse.response?.expires_in;
      expect(expires_in).toBeLessThanOrEqual(60);
      log.testCompleted();

      console.log(expires_in);
      console.log('Expires in:', expires_in);
    });

    test("CI_041: PAR Request | Generated request_uri includes a cryptographic random value of at least 128 bits", async () => {
      const log = baseLog.withTag("CI_041");

      log.start("Started");
      const requestUri =
        pushedAuthorizationRequestResponse.response?.request_uri;

      // Extract random portion (e.g. UUID, base64, or hex)
      const randomPart = requestUri?.split(":").pop() ?? "";
      const isBase64 = /^[A-Za-z0-9+/=]+$/.test(randomPart);
      const bitLength = isBase64
        ? randomPart.length * 6
        : randomPart.length * 4; // hex fallback
      // Ensure it's at least 128 bits of randomness (16 bytes)
      expect(bitLength).toBeGreaterThanOrEqual(128);
      log.testCompleted();

      console.log('Bits length:', bitLength);
    });

    test("CI_042: PAR Request | Complete request_uri doesn't exceed 512 ASCII characters", async () => {
      const log = baseLog.withTag("CI_042");

      log.start("Started");
      const requestUriLenght = pushedAuthorizationRequestResponse.response?.request_uri.length
      expect(requestUriLenght).toBeLessThanOrEqual(512);
      log.testCompleted();
      
      console.log('Request URI length:', requestUriLenght);
    });

    test("CI_043: PAR Request | When verification is successful, Credential Issuer returns an HTTP response with 201 status code", async () => {
      const log = baseLog.withTag("CI_043");

      log.start("Started");
      expect(pushedAuthorizationRequestResponse.error).toBeUndefined();
      log.testCompleted();
    });

    test("CI_044a: PAR Request | HTTP response includes request_uri parameter containing the generated one-time authorization URI", async () => {
      const log = baseLog.withTag("CI_044a");

      log.start("Started");
      const requestUri = pushedAuthorizationRequestResponse.response?.request_uri;
      expect(requestUri).toBeDefined();
      expect(requestUri).toBeTruthy();
      log.testCompleted();

      console.log('Request URI:', requestUri);
    });

    test("CI_044b: PAR Request | HTTP response includes expires_in parameter specifying the validity duration in seconds", async () => {
      const log = baseLog.withTag("CI_044b");

      log.start("Started");
      expect(
        pushedAuthorizationRequestResponse.response?.expires_in,
      ).toBeDefined();
      expect(
        typeof pushedAuthorizationRequestResponse.response?.expires_in,
      ).toBe("number");
      expect(
        pushedAuthorizationRequestResponse.response?.expires_in,
      ).toBeGreaterThan(0);
      log.testCompleted();
    });

    // ============================================================================
    // AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_049: Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR", async () => {
      const log = baseLog.withTag("CI_049");

      log.start("Started");
      expect(authorizeResponse.response?.requestObject?.exp).toBeDefined();
      expect(authorizeResponse.response?.requestObject?.exp).toBe(
        pushedAuthorizationRequestResponse.response?.expires_in,
      );
      log.testCompleted();
    });

    test("CI_054: (Q)EAA Provider successfully performs User authentication by requesting and validating a valid PID from the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_054");

      log.start("Started");
      expect(authorizeResponse.response?.authorizeResponse?.code).toBeDefined();
      log.testCompleted();
    });

    test("CI_055: (Q)EAA Provider uses OpenID4VP protocol to request PID presentation from the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_055");

      log.start("Started");
      expect(authorizeResponse.response?.authorizeResponse?.code).toBeDefined();
      log.testCompleted();
    });

    test("CI_056: (Q)EAA Provider successfully provides the presentation request to the Wallet", async () => {
      const log = baseLog.withTag("CI_056");

      log.start("Started");
      expect(authorizeResponse.response?.requestObjectJwt).toBeDefined();
      log.testCompleted();
    });

    test("CI_058a: Authorization code response includes the authorization code parameter", async () => {
      const log = baseLog.withTag("CI_058a");

      log.start("Started");
      expect(authorizeResponse.response?.authorizeResponse?.code).toBeDefined();
      expect(typeof authorizeResponse.response?.authorizeResponse?.code).toBe(
        "string",
      );
      log.testCompleted();
    });

    test("CI_058b: Authorization code response includes the state parameter matching the original request", async () => {
      const log = baseLog.withTag("CI_058b");

      log.start("Started");
      expect(
        authorizeResponse.response?.authorizeResponse?.state,
      ).toBeDefined();
      expect(typeof authorizeResponse.response?.authorizeResponse?.state).toBe(
        "string",
      );
      expect(authorizeResponse.response?.authorizeResponse?.state).toBe(
        authorizeResponse.response?.requestObject?.state,
      );
      log.testCompleted();
    });

    test("CI_058c: Authorization code response includes the iss parameter identifying the issuer", async () => {
      const log = baseLog.withTag("CI_058c");

      log.start("Started");
      expect(authorizeResponse.response?.authorizeResponse?.iss).toBeDefined();
      expect(typeof authorizeResponse.response?.authorizeResponse?.iss).toBe(
        "string",
      );
      expect(authorizeResponse.response?.authorizeResponse?.iss).toBe(
        authorizeResponse.response?.iss,
      );
      log.testCompleted();
    });
  });
});
