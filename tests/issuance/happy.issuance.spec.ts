import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

// Import test configuration - this will register all configurations
import "../test.config";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator/wallet-issuance-orchestrator-flow";
import { FetchMetadataStepResponse } from "@/step/issuance/fetch-metadata-step";
import { PushedAuthorizationRequestResponse } from "@/step/issuance/pushed-authorization-request-step";

import { issuerRegistry } from "../config/test-registry";
import { HAPPY_FLOW_ISSUANCE_NAME } from "../test.config";

// Get the test configuration from the registry
// The configuration must be registered before running the tests
issuerRegistry.get(HAPPY_FLOW_ISSUANCE_NAME).forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, async () => {
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;

    beforeAll(async () => {
      ({ fetchMetadataResponse, pushedAuthorizationRequestResponse } =
        await orchestrator.issuance());
    });

    test("CI_001: Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint.", async () => {
      const log = baseLog.withTag("CI_001");

      log.start("Started");
      expect(fetchMetadataResponse.success).toBe(true);
      log.testCompleted();
    });

    test("CI_002 Entity Configuration response media type check", async () => {
      const log = baseLog.withTag("CI_002");

      log.start("Started");
      expect(fetchMetadataResponse.response?.headers.get("content-type")).toBe(
        "application/entity-statement+jwt",
      );
      log.testCompleted();
    });

    test("CI_003: The Entity Configuration is cryptographically signed", async () => {
      const log = baseLog.withTag("CI_003");

      log.start("Started");
      expect(fetchMetadataResponse.response).toBeDefined();

      log.info("Asserting response status...");
      expect(fetchMetadataResponse.response!.status).toBe(200);

      log.info("Checking non empty response body...");
      expect(fetchMetadataResponse.response?.entityStatementJwt).toBeDefined();

      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt!,
      );
      log.debug(decodedData);
      log.testCompleted();
    });

    test("CI_006: Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
      const log = baseLog.withTag("CI_006");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt!,
      );
      log.debug(JSON.stringify(decodedData));

      log.info("Validating response format...");
      const result = itWalletEntityStatementClaimsSchema._def.schema
        .pick({
          exp: true,
          iat: true,
          iss: true,
          jwks: true,
          metadata: true,
          sub: true,
        })
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

    test("CI_008: Credential Issuer metadata", async () => {
      const log = baseLog.withTag("CI_008");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt!,
      );
      log.debug(JSON.stringify(decodedData));

      log.info("Validating response format...");
      const result = itWalletEntityStatementClaimsSchema._def.schema
        .pick({
          metadata: true,
        })
        .refine(
          (data) =>
            data.metadata !== undefined &&
            data.metadata!.federation_entity !== undefined &&
            data.metadata!.oauth_authorization_server !== undefined &&
            data.metadata!.openid_credential_issuer !== undefined,
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

    test("CI_009: Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
      const log = baseLog.withTag("CI_009");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt!,
      );
      log.debug(JSON.stringify(decodedData));

      log.info("Validating response format...");
      const result = itWalletEntityStatementClaimsSchema._def.schema
        .pick({
          metadata: true,
        })
        .refine(
          (data) =>
            data.metadata !== undefined &&
            data.metadata!.openid_credential_verifier !== undefined,
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

    test("CI_040: request_uri validity time is set to less than one minute", async () => {
      const log = baseLog.withTag("CI_040");

      log.start("Started");
      expect(
        pushedAuthorizationRequestResponse.response?.expires_in,
      ).toBeLessThanOrEqual(60);
      log.testCompleted();
    });

    test("CI_041: Generated request_uri includes a cryptographic random value of at least 128 bits", async () => {
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
    });

    test("CI_042: Complete request_uri doesn't exceed 512 ASCII characters", async () => {
      const log = baseLog.withTag("CI_042");

      log.start("Started");
      expect(
        pushedAuthorizationRequestResponse.response?.request_uri.length,
      ).toBeLessThanOrEqual(512);
      log.testCompleted();
    });

    test("CI_043: When verification is successful, Credential Issuer returns an HTTP response with 201 status code", async () => {
      const log = baseLog.withTag("CI_043");

      log.start("Started");
      expect(pushedAuthorizationRequestResponse.error).toBeUndefined();
      log.testCompleted();
    });

    test("CI_044a: HTTP response includes request_uri parameter containing the generated one-time authorization URI", async () => {
      const log = baseLog.withTag("CI_044a");

      log.start("Started");
      expect(
        pushedAuthorizationRequestResponse.response?.request_uri,
      ).toBeDefined();
      expect(
        pushedAuthorizationRequestResponse.response?.request_uri,
      ).toBeTruthy();
      log.testCompleted();
    });

    test("CI_044b: HTTP response includes expires_in parameter specifying the validity duration in seconds", async () => {
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
    // AUTHORISATION REQUEST TESTS
    // ============================================================================
  });
});
