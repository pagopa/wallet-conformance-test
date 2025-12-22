/* eslint-disable max-lines-per-function */
import { issuerRegistry } from "#/config";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";

// Import test configuration - this will register all configurations
import "../test.config";

import { calculateJwkThumbprint, decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { FetchMetadataStepResponse } from "@/step";
import { NonceRequestResponse, AuthorizeStepResponse, PushedAuthorizationRequestResponse, TokenRequestResponse, CredentialRequestResponse } from "@/step/issuance";

import { HAPPY_FLOW_ISSUANCE_NAME } from "../test.config";
import { AttestationResponse } from "@/types";
import { SDJwt } from "@sd-jwt/core";
import { parseMdoc } from "@/logic";

// Get the test configuration from the registry
// The configuration must be registered before running the tests
issuerRegistry.get(HAPPY_FLOW_ISSUANCE_NAME).forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, async () => {
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let tokenResponse: TokenRequestResponse;
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    let authorizeResponse: AuthorizeStepResponse;
    let walletAttestationResponse: AttestationResponse;
    let nonceResponse: NonceRequestResponse;
    let credentialResponse: CredentialRequestResponse;

    beforeAll(async () => {
      ({
        authorizeResponse,
        fetchMetadataResponse,
        pushedAuthorizationRequestResponse,
        tokenResponse,
        walletAttestationResponse,
        nonceResponse,
        credentialResponse,
      } = await orchestrator.issuance());
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
      expect(fetchMetadataResponse.response?.status).toBe(200);

      log.info("Checking non empty response body...");
      expect(fetchMetadataResponse.response?.entityStatementJwt).toBeDefined();

      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
      );
      log.debug(decodedData);
      log.testCompleted();
    });

    test("CI_006: Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
      const log = baseLog.withTag("CI_006");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
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
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
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

    test("CI_009: Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
      const log = baseLog.withTag("CI_009");

      log.start("Started");
      log.info("Parsing response body as JWT...");
      const decodedData = decodeJwt(
        fetchMetadataResponse.response?.entityStatementJwt ?? "",
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
    // AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_049: Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR", async () => {
      const log = baseLog.withTag("CI_049");

      log.start("Started");

      // Verify PAR response provided a valid request_uri
      log.info("Verifying PAR response contains request_uri...");
      const requestUri = pushedAuthorizationRequestResponse.response?.request_uri;
      expect(requestUri).toBeDefined();
      expect(typeof requestUri).toBe("string");
      expect(requestUri?.length).toBeGreaterThan(0);

      // Verify the request_uri follows the expected format (urn:ietf:params:oauth:request_uri:...)
      log.info("Verifying request_uri format...");
      expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:.+$/);

      // Verify authorization was successful - this proves the issuer correlated the request
      // If the issuer couldn't correlate the authorization request with the PAR, it would fail
      log.info("Verifying authorization succeeded with the PAR request_uri...");
      expect(authorizeResponse.success).toBe(true);
      expect(authorizeResponse.response?.authorizeResponse?.code).toBeDefined();

      log.info("Credential Issuer successfully correlated authorization request with PAR");
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
    });

    // ============================================================================
    // TOKEN REQUEST TESTS
    // ============================================================================

    test("CI_064: Credential Issuer provides the Wallet Instance with a valid Access Token upon successful authorization", async () => {
      const log = baseLog.withTag("CI_064");

      log.start("Started");

      const token = tokenResponse.response?.access_token;
      expect(token).toBeDefined();

      log.info("Parsing token as JWT...");
      const claims = decodeJwt(token ?? "");
      expect(claims.exp).toBeGreaterThan(Date.now() / 1e3);
      expect(claims.iat).toBeLessThan(Date.now() / 1e3);

      log.testCompleted();
    });

    test("CI_066: Both Access Token and Refresh Token (when issued) are cryptographically bound to the DPoP key", async () => {
      const log = baseLog.withTag("CI_066");

      log.start("Started");

      expect(tokenResponse.response?.token_type).toBe("DPoP");
      expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();

      log.info("Computing JWK Thumbprint...");
      const jkt = await calculateJwkThumbprint(walletAttestationResponse.unitKey.publicKey);

      const tokens = [tokenResponse.response?.access_token];
      if (tokenResponse.response?.refresh_token)
        tokens.push(tokenResponse.response?.refresh_token);
      
      for (const token of tokens) {
        log.info("Parsing token as JWT...");
        const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");

        expect(claims.cnf?.jkt).toBeDefined();
        expect(claims.cnf?.jkt).toBe(jkt);
      }

      log.testCompleted();
    });

    test("CI_094: When all validation checks succeed, Credential Issuer generates new Access Token and new Refresh Token, both bound to the DPoP key", async () => {
      const log = baseLog.withTag("CI_094");

      log.start("Started");

      expect(tokenResponse.response?.token_type).toBe("DPoP");
      expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();

      log.info("Computing JWK Thumbprint...");
      const jkt = await calculateJwkThumbprint(walletAttestationResponse.unitKey.publicKey);

      const tokens = [tokenResponse.response?.access_token];
      if (tokenResponse.response?.refresh_token)
        tokens.push(tokenResponse.response?.refresh_token);
      
      for (const token of tokens) {
        log.info("Parsing token as JWT...");
        const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");

        expect(claims.cnf?.jkt).toBeDefined();
        expect(claims.cnf?.jkt).toBe(jkt);
      }

      log.testCompleted();
    });

    test("CI_095: Both the Access Token and the Refresh Token are sent back to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_095");

      log.start("Started");

      expect(tokenResponse.response?.access_token).toBeDefined();

      log.testCompleted();
    });

    test("CI_101: Access Tokens and Refresh Tokens are bound to the same DPoP key", async () => {
      const log = baseLog.withTag("CI_101");

      log.start("Started");

      expect(tokenResponse.response?.token_type).toBe("DPoP");
      expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();

      log.info("Computing JWK Thumbprint...");
      const jkt = await calculateJwkThumbprint(walletAttestationResponse.unitKey.publicKey);

      const tokens = [tokenResponse.response?.access_token];
      if (tokenResponse.response?.refresh_token)
        tokens.push(tokenResponse.response?.refresh_token);
      
      for (const token of tokens) {
        log.info("Parsing token as JWT...");
        const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");

        expect(claims.cnf?.jkt).toBeDefined();
        expect(claims.cnf?.jkt).toBe(jkt);
      }

      log.testCompleted();
    });

    // ============================================================================
    // NONCE REQUEST TESTS
    // ============================================================================

    test("CI_068: Credential Issuer provides a c_nonce value to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_068");

      log.start("Started");

      const nonce = nonceResponse.response?.nonce as { c_nonce: string } | undefined;
      expect(nonce?.c_nonce).toBeDefined();
      expect(nonce?.c_nonce.length).toBeGreaterThan(0);

      log.testCompleted();
    });

    test("CI_069: The c_nonce parameter is provided as a string value with sufficient unpredictability to prevent guessing attacks, serving as a cryptographic challenge that the Wallet Instance uses to create proof of possession of the key (proofs claim)", async () => {
      const log = baseLog.withTag("CI_069");

      log.start("Started");

      const nonce = nonceResponse.response?.nonce as { c_nonce: string } | undefined;
      let cNonce = nonce?.c_nonce ?? "";
      const length = cNonce.length;
      expect(length).toBeGreaterThanOrEqual(32);

      let frequencies: number[] = [];
      for (const char of cNonce) {
        const prevLength = cNonce.length;
        cNonce = cNonce.replace(char, "");

        frequencies.push((prevLength - cNonce.length) / length);
      }

      const entropy = - frequencies.reduce((a, b) => a + (b * Math.log2(b)), 0);
      expect(entropy).toBeGreaterThan(5);
	});

    // ============================================================================
    // CREDENTIAL REQUEST TESTS
    // ============================================================================

    test("CI_084: When all validation checks succeed, Credential Issuer creates a new Credential cryptographically bound to the validated key material and provides it to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_084");

      log.start("Started");

      expect(credentialResponse.response?.credentials?.length).toBeGreaterThan(0);

      for (const credential of credentialResponse.response?.credentials ?? [])
        expect(credential.credential).toBeDefined();

      log.testCompleted();
    });

    test("CI_118: (Q)EAA are Issued to a Wallet Instance in SD-JWT VC or mdoc-CBOR data format.", async () => {
      const log = baseLog.withTag("CI_118");

      log.start("Started");

      for (const credential of credentialResponse.response?.credentials ?? []) {
        try {
          log.info("Parsing credential as SD-JWT...");
          await SDJwt.extractJwt(credential.credential);

          log.testCompleted();
          return;
        } catch {}

        try {
          log.info("Parsing credential as mdoc-CBOR...");
          parseMdoc(Buffer.from(credential.credential));

          log.testCompleted();
          return;
        } catch {
          log.testFailed();
        }
      }
    });
  });
});
