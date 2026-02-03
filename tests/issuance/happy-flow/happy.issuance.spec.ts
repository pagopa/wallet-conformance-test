/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { SDJwt } from "@sd-jwt/core";
import { calculateJwkThumbprint, decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import z from "zod/v3";

import { parseMdoc } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { FetchMetadataStepResponse } from "@/step";
import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  NonceRequestResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";

// Define and auto-register test configuration
const testConfigs = await defineIssuanceTest("HappyFlowIssuance");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, () => {
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
        baseLog.info("========================================");
        baseLog.info("🚀 Starting Issuance Flow Conformance Tests");
        baseLog.info("========================================");
        baseLog.info("");

        try {
          ({
            authorizeResponse,
            credentialResponse,
            fetchMetadataResponse,
            nonceResponse,
            pushedAuthorizationRequestResponse,
            tokenResponse,
            walletAttestationResponse,
          } = await orchestrator.issuance());

          baseLog.info("");
          baseLog.info("✅ Issuance flow completed");
          baseLog.info("✅ Your implementation works correctly!");
          baseLog.info("========================================");
          baseLog.info("📋 Running conformance validation tests...");
          baseLog.info("");
        } catch (e) {
          baseLog.error("❌ Issuance flow failed with error:", e);
          baseLog.error("❌ Your implementation did not complete the issuance flow.");
          baseLog.error("========================================");
          throw e;
        } finally {
          // Give time for all logs to be flushed before starting tests
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      });

      test("CI_001: Fetch Metadata | Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint.", async () => {
        const log = baseLog.withTag("CI_001");

        log.start(
          "Conformance test: Verifying Entity Configuration availability",
        );

        let testSuccess = false;
        try {
          log.info("→ Checking Entity Configuration fetch was successful...");
          expect(fetchMetadataResponse.success).toBe(true);
          log.info("  ✅ Entity Configuration successfully fetched");

          log.info("→ Validating Entity Statement claims are present...");
          expect(
            fetchMetadataResponse.response?.entityStatementClaims,
          ).toBeDefined();
          log.info("  ✅ Entity Statement claims are present");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_002: Fetch Metadata | Entity Configuration response media type check", async () => {
        const log = baseLog.withTag("CI_002");

        log.start(
          "Conformance test: Verifying Entity Configuration content-type header",
        );

        let testSuccess = false;
        try {
          const expectedContentType = "application/entity-statement+jwt";
          const actualContentType =
            fetchMetadataResponse.response?.headers.get("content-type");

          log.info("→ Validating content-type header...");
          log.info(`  Expected: ${expectedContentType}`);
          log.info(`  Actual: ${actualContentType}`);
          expect(actualContentType).toBe(expectedContentType);
          log.info("  ✅ content-type header is correct");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_003: Fetch Metadata | The Entity Configuration is cryptographically signed", async () => {
        const log = baseLog.withTag("CI_003");

        log.start(
          "Conformance test: Verifying Entity Configuration JWT signature",
        );

        let testSuccess = false;
        try {
          log.info("→ Validating response is present...");
          expect(fetchMetadataResponse.response).toBeDefined();
          log.info("  ✅ Response is present");

          log.info("→ Asserting response status...");
          expect(fetchMetadataResponse.response?.status).toBe(200);
          log.info("  ✅ Response status is 200");

          log.info("→ Checking Entity Statement JWT is present...");
          expect(
            fetchMetadataResponse.response?.entityStatementJwt,
          ).toBeDefined();
          log.info("  ✅ Entity Statement JWT is present");

          log.info("→ Parsing response body as JWT...");
          const decodedData = decodeJwt(
            fetchMetadataResponse.response?.entityStatementJwt ?? "",
          );
          expect(decodedData).toBeDefined();
          log.info("  ✅ JWT successfully decoded and verified");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_006: Fetch Metadata | Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
        const log = baseLog.withTag("CI_006");

        log.start(
          "Conformance test: Verifying Entity Configuration mandatory parameters",
        );

        let testSuccess = false;
        try {
          log.info("→ Parsing response body as JWT...");
          const decodedData = decodeJwt(
            fetchMetadataResponse.response?.entityStatementJwt ?? "",
          );
          log.info("  ✅ JWT successfully parsed");

          log.info(
            "→ Validating required parameters (iss, sub, iat, exp, jwks, metadata)...",
          );
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
          log.info("  ✅ All required parameters are present and valid");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_008: Fetch Metadata | Credential Issuer metadata", async () => {
        const log = baseLog.withTag("CI_008");

        log.start(
          "Conformance test: Verifying Credential Issuer metadata structure",
        );

        let testSuccess = false;
        try {
          log.info("→ Parsing response body as JWT...");
          const decodedData = decodeJwt(
            fetchMetadataResponse.response?.entityStatementJwt ?? "",
          );
          log.info("  ✅ JWT successfully parsed");

          log.info("→ Validating Credential Issuer metadata structure...");
          log.info("  Required metadata sections:");
          log.info("    - federation_entity");
          log.info("    - oauth_authorization_server");
          log.info("    - openid_credential_issuer");

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

          log.info("  ✅ All required metadata sections are present");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_009: Fetch Metadata | Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
        const log = baseLog.withTag("CI_009");

        log.start(
          "Conformance test: Verifying openid_credential_verifier metadata presence",
        );

        let testSuccess = false;
        try {
          log.info("→ Parsing response body as JWT...");
          const decodedData = decodeJwt(
            fetchMetadataResponse.response?.entityStatementJwt ?? "",
          );
          log.info("  ✅ JWT successfully parsed");

          log.info("→ Checking openid_credential_verifier metadata...");
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

          log.info("  ✅ openid_credential_verifier metadata is present");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      // ============================================================================
      // PUSHED AUTHORIZATION REQUEST TESTS
      // ============================================================================

      test("CI_040: PAR Request | request_uri validity time is set to less than one minute", async () => {
        const log = baseLog.withTag("CI_040");

        log.start("Conformance test: Verifying request_uri expiration time");

        let testSuccess = false;
        try {
          log.info("→ Checking request_uri expiration time...");
          const expires_in =
            pushedAuthorizationRequestResponse.response?.expires_in;
          expect(expires_in).toBeDefined();
          log.info(`  expires_in: ${expires_in} seconds`);
          expect(expires_in).toBeLessThanOrEqual(60);
          log.info("  ✅ expires_in is ≤60 seconds (compliant)");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_041: PAR Request | Generated request_uri includes a cryptographic random value of at least 128 bits", async () => {
        const log = baseLog.withTag("CI_041");

        log.start(
          "Conformance test: Verifying request_uri entropy requirements",
        );

        let testSuccess = false;
        try {
          const requestUri =
            pushedAuthorizationRequestResponse.response?.request_uri;
          expect(requestUri).toBeDefined();

          log.info("→ Analyzing request_uri random value entropy...");
          log.info(`  request_uri: ${requestUri}`);

          // Extract random portion (e.g. UUID, base64, or hex)
          const randomPart = requestUri?.split(":").pop() ?? "";
          const isBase64 = /^[A-Za-z0-9+/=]+$/.test(randomPart);
          const bitLength = isBase64
            ? randomPart.length * 6
            : randomPart.length * 4; // hex fallback

          log.info(`  Random part: ${randomPart}`);
          log.info(`  Bit length: ${bitLength} bits`);
          log.info(`  Required: ≥128 bits`);

          // Ensure it's at least 128 bits of randomness (16 bytes)
          expect(bitLength).toBeGreaterThanOrEqual(128);
          log.info("  ✅ Sufficient entropy (≥128 bits)");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_042: PAR Request | Complete request_uri doesn't exceed 512 ASCII characters", async () => {
        const log = baseLog.withTag("CI_042");

        log.start("Conformance test: Verifying request_uri length constraint");

        let testSuccess = false;
        try {
          log.info("→ Checking request_uri length...");
          const requestUriLength =
            pushedAuthorizationRequestResponse.response?.request_uri.length;
          expect(requestUriLength).toBeDefined();
          log.info(`  Length: ${requestUriLength} characters`);
          log.info(`  Maximum: 512 characters`);
          expect(requestUriLength).toBeLessThanOrEqual(512);
          log.info("  ✅ request_uri length is compliant (≤512 characters)");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_043: PAR Request | When verification is successful, Credential Issuer returns an HTTP response with 201 status code", async () => {
        const log = baseLog.withTag("CI_043");

        log.start("Conformance test: Verifying PAR request success response");

        let testSuccess = false;
        try {
          log.info("→ Checking PAR request completed without errors...");
          expect(pushedAuthorizationRequestResponse.error).toBeUndefined();
          log.info("  ✅ PAR request successful (no errors)");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_044a: PAR Request | HTTP response includes request_uri parameter containing the generated one-time authorization URI", async () => {
        const log = baseLog.withTag("CI_044a");

        log.start("Conformance test: Verifying request_uri parameter presence");

        let testSuccess = false;
        try {
          log.info("→ Checking request_uri parameter...");
          const requestUri =
            pushedAuthorizationRequestResponse.response?.request_uri;
          expect(requestUri).toBeDefined();
          expect(requestUri).toBeTruthy();
          log.info(`  request_uri: ${requestUri}`);
          log.info("  ✅ request_uri parameter is present");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_044b: PAR Request | HTTP response includes expires_in parameter specifying the validity duration in seconds", async () => {
        const log = baseLog.withTag("CI_044b");

        log.start("Conformance test: Verifying expires_in parameter");

        let testSuccess = false;
        try {
          log.info("→ Checking expires_in parameter...");
          const expiresIn =
            pushedAuthorizationRequestResponse.response?.expires_in;
          expect(expiresIn).toBeDefined();
          expect(typeof expiresIn).toBe("number");
          log.info(`  expires_in: ${expiresIn} seconds`);
          expect(expiresIn).toBeGreaterThan(0);
          log.info("  ✅ expires_in parameter is present and valid");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      // ============================================================================
      // AUTHORIZATION REQUEST TESTS
      // ============================================================================

      test("CI_049: Authorization | Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR", async () => {
        const log = baseLog.withTag("CI_049");

        log.start(
          "Conformance test: Verifying PAR and authorization request correlation",
        );

        let testSuccess = false;
        try {
          // Verify PAR response provided a valid request_uri
          log.info("→ Verifying PAR response contains request_uri...");
          const requestUri =
            pushedAuthorizationRequestResponse.response?.request_uri;
          expect(requestUri).toBeDefined();
          expect(typeof requestUri).toBe("string");
          expect(requestUri?.length).toBeGreaterThan(0);
          log.info("  ✅ PAR response includes request_uri");

          // Verify the request_uri follows the expected format (urn:ietf:params:oauth:request_uri:...)
          log.info("→ Verifying request_uri format...");
          log.info(`  request_uri: ${requestUri}`);
          expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:.+$/);
          log.info("  ✅ request_uri format is correct");

          // Verify authorization was successful - this proves the issuer correlated the request
          // If the issuer couldn't correlate the authorization request with the PAR, it would fail
          log.info(
            "→ Verifying authorization succeeded with the PAR request_uri...",
          );
          expect(authorizeResponse.success).toBe(true);
          expect(
            authorizeResponse.response?.authorizeResponse?.code,
          ).toBeDefined();
          log.info(
            "  ✅ Authorization successful - issuer correlated PAR and authorization",
          );

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_054: Authorization | (Q)EAA Provider successfully performs User authentication by requesting and validating a valid PID from the Wallet Instance", async () => {
        const log = baseLog.withTag("CI_054");

        log.start("Conformance test: Verifying PID-based user authentication");

        let testSuccess = false;
        try {
          log.info("→ Checking authorization code presence...");
          expect(
            authorizeResponse.response?.authorizeResponse?.code,
          ).toBeDefined();
          log.info(
            "  ✅ Authorization code received (user authentication successful)",
          );

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_055: Authorization | (Q)EAA Provider uses OpenID4VP protocol to request PID presentation from the Wallet Instance", async () => {
        const log = baseLog.withTag("CI_055");

        log.start("Conformance test: Verifying OpenID4VP protocol usage");

        let testSuccess = false;
        try {
          log.info("→ Checking OpenID4VP presentation flow completed...");
          expect(
            authorizeResponse.response?.authorizeResponse?.code,
          ).toBeDefined();
          log.info(
            "  ✅ OpenID4VP presentation successful (authorization code received)",
          );

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_056: Authorization | (Q)EAA Provider successfully provides the presentation request to the Wallet", async () => {
        const log = baseLog.withTag("CI_056");

        log.start("Conformance test: Verifying presentation request delivery");

        let testSuccess = false;
        try {
          log.info("→ Checking presentation request JWT was received...");
          expect(authorizeResponse.response?.requestObjectJwt).toBeDefined();
          log.info("  ✅ Presentation request JWT successfully received");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_058a: Authorization | Authorization code response includes the authorization code parameter", async () => {
        const log = baseLog.withTag("CI_058a");

        log.start("Conformance test: Verifying authorization code parameter");

        let testSuccess = false;
        try {
          log.info("→ Checking authorization code parameter...");
          const code = authorizeResponse.response?.authorizeResponse?.code;
          expect(code).toBeDefined();
          expect(typeof code).toBe("string");
          log.info(`  code: ${code}`);
          log.info("  ✅ Authorization code parameter is present and valid");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_058b: Authorization | Authorization code response includes the state parameter matching the original request", async () => {
        const log = baseLog.withTag("CI_058b");

        log.start("Conformance test: Verifying state parameter matching");

        let testSuccess = false;
        try {
          log.info("→ Checking state parameter...");
          const responseState =
            authorizeResponse.response?.authorizeResponse?.state;
          const requestState = authorizeResponse.response?.requestObject?.state;

          expect(responseState).toBeDefined();
          expect(typeof responseState).toBe("string");
          log.info(`  Response state: ${responseState}`);
          log.info(`  Request state: ${requestState}`);

          expect(responseState).toBe(requestState);
          log.info("  ✅ State parameter matches original request");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_058c: Authorization | Authorization code response includes the iss parameter identifying the issuer", async () => {
        const log = baseLog.withTag("CI_058c");

        log.start(
          "Conformance test: Verifying issuer identification parameter",
        );

        let testSuccess = false;
        try {
          log.info("→ Checking iss parameter...");
          const responseIss =
            authorizeResponse.response?.authorizeResponse?.iss;
          const expectedIss = authorizeResponse.response?.iss;

          expect(responseIss).toBeDefined();
          expect(typeof responseIss).toBe("string");
          log.info(`  Response iss: ${responseIss}`);
          log.info(`  Expected iss: ${expectedIss}`);

          expect(responseIss).toBe(expectedIss);
          log.info("  ✅ Issuer parameter is present and matches");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      // ============================================================================
      // TOKEN REQUEST TESTS
      // ============================================================================

      test("CI_064: Token | Credential Issuer provides the Wallet Instance with a valid Access Token upon successful authorization", async () => {
        const log = baseLog.withTag("CI_064");

        log.start(
          "Conformance test: Verifying Access Token issuance and validity",
        );

        let testSuccess = false;
        try {
          log.info("→ Checking Access Token presence...");
          const token = tokenResponse.response?.access_token;
          expect(token).toBeDefined();
          log.info("  ✅ Access Token is present");

          log.info("→ Parsing and validating token claims...");
          const claims = decodeJwt(token ?? "");
          const currentTime = Date.now() / 1e3;

          log.info(
            `  Issued at (iat): ${new Date(claims.iat! * 1000).toISOString()}`,
          );
          log.info(
            `  Expires at (exp): ${new Date(claims.exp! * 1000).toISOString()}`,
          );
          log.info(
            `  Current time: ${new Date(currentTime * 1000).toISOString()}`,
          );

          expect(claims.exp).toBeGreaterThan(currentTime);
          expect(claims.iat).toBeLessThan(currentTime);
          log.info("  ✅ Token is valid and not expired");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_066: Token | Both Access Token and Refresh Token (when issued) are cryptographically bound to the DPoP key", async () => {
        const log = baseLog.withTag("CI_066");

        log.start("Conformance test: Verifying DPoP key binding");

        let testSuccess = false;
        try {
          log.info("→ Checking token type...");
          expect(tokenResponse.response?.token_type).toBe("DPoP");
          log.info("  ✅ Token type is DPoP");

          log.info("→ Computing JWK Thumbprint from wallet key...");
          expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();
          const jkt = await calculateJwkThumbprint(
            walletAttestationResponse.unitKey.publicKey,
          );
          log.info(`  JWK Thumbprint: ${jkt}`);

          const tokens = [tokenResponse.response?.access_token];
          if (tokenResponse.response?.refresh_token) {
            tokens.push(tokenResponse.response?.refresh_token);
            log.info("  Both Access Token and Refresh Token will be validated");
          } else {
            log.info(
              "  Only Access Token will be validated (no Refresh Token)",
            );
          }

          log.info("→ Validating DPoP binding in tokens...");
          for (const token of tokens) {
            const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
            expect(claims.cnf?.jkt).toBeDefined();
            expect(claims.cnf?.jkt).toBe(jkt);
          }
          log.info("  ✅ All tokens are bound to the DPoP key");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_094: Token | When all validation checks succeed, Credential Issuer generates new Access Token and new Refresh Token, both bound to the DPoP key", async () => {
        const log = baseLog.withTag("CI_094");

        log.start(
          "Conformance test: Verifying token generation with DPoP binding",
        );

        let testSuccess = false;
        try {
          log.info("→ Checking token type...");
          expect(tokenResponse.response?.token_type).toBe("DPoP");
          log.info("  ✅ Token type is DPoP");

          log.info("→ Computing JWK Thumbprint...");
          expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();
          const jkt = await calculateJwkThumbprint(
            walletAttestationResponse.unitKey.publicKey,
          );
          log.info(`  JWK Thumbprint: ${jkt}`);

          const tokens = [tokenResponse.response?.access_token];
          if (tokenResponse.response?.refresh_token) {
            tokens.push(tokenResponse.response?.refresh_token);
          }

          log.info("→ Validating DPoP binding in generated tokens...");
          for (const token of tokens) {
            const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
            expect(claims.cnf?.jkt).toBeDefined();
            expect(claims.cnf?.jkt).toBe(jkt);
          }
          log.info("  ✅ Tokens generated and bound to DPoP key");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_095: Token | Both the Access Token and the Refresh Token are sent back to the Wallet Instance", async () => {
        const log = baseLog.withTag("CI_095");

        log.start("Conformance test: Verifying token response delivery");

        let testSuccess = false;
        try {
          log.info("→ Checking Access Token presence...");
          expect(tokenResponse.response?.access_token).toBeDefined();
          log.info("  ✅ Access Token is present");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_101: Token | Access Tokens and Refresh Tokens are bound to the same DPoP key", async () => {
        const log = baseLog.withTag("CI_101");

        log.start(
          "Conformance test: Verifying consistent DPoP key binding across tokens",
        );

        let testSuccess = false;
        try {
          log.info("→ Checking token type...");
          expect(tokenResponse.response?.token_type).toBe("DPoP");
          log.info("  ✅ Token type is DPoP");

          log.info("→ Computing JWK Thumbprint...");
          expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();
          const jkt = await calculateJwkThumbprint(
            walletAttestationResponse.unitKey.publicKey,
          );
          log.info(`  JWK Thumbprint: ${jkt}`);

          const tokens = [tokenResponse.response?.access_token];
          if (tokenResponse.response?.refresh_token) {
            tokens.push(tokenResponse.response?.refresh_token);
          }

          log.info(
            "→ Validating all tokens share the same DPoP key binding...",
          );
          for (const token of tokens) {
            const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
            expect(claims.cnf?.jkt).toBeDefined();
            expect(claims.cnf?.jkt).toBe(jkt);
          }
          log.info("  ✅ All tokens bound to the same DPoP key");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      // ============================================================================
      // NONCE REQUEST TESTS
      // ============================================================================

      test("CI_068: Nonce | Credential Issuer provides a c_nonce value to the Wallet Instance", async () => {
        const log = baseLog.withTag("CI_068");

        log.start("Conformance test: Verifying c_nonce parameter provision");

        let testSuccess = false;
        try {
          log.info("→ Checking c_nonce parameter...");
          const nonce = nonceResponse.response?.nonce as
            | undefined
            | { c_nonce: string };
          expect(nonce?.c_nonce).toBeDefined();
          expect(nonce?.c_nonce.length).toBeGreaterThan(0);
          log.info(`  c_nonce: ${nonce?.c_nonce}`);
          log.info(`  Length: ${nonce?.c_nonce.length} characters`);
          log.info("  ✅ c_nonce parameter is present and non-empty");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_069: Nonce | The c_nonce parameter is provided as a string value with sufficient unpredictability to prevent guessing attacks, serving as a cryptographic challenge that the Wallet Instance uses to create proof of possession of the key (proofs claim)", async () => {
        const log = baseLog.withTag("CI_069");

        log.start(
          "Conformance test: Verifying c_nonce entropy and unpredictability",
        );

        let testSuccess = false;
        try {
          const nonce = nonceResponse.response?.nonce as
            | undefined
            | { c_nonce: string };
          let cNonce = nonce?.c_nonce ?? "";
          const length = cNonce.length;

          log.info("→ Checking c_nonce length...");
          log.info(`  Length: ${length} characters`);
          log.info(`  Required: ≥32 characters`);
          expect(length).toBeGreaterThanOrEqual(32);
          log.info("  ✅ c_nonce length is sufficient");

          log.info("→ Computing entropy...");
          const frequencies: number[] = [];
          for (const char of cNonce) {
            const prevLength = cNonce.length;
            cNonce = cNonce.replace(char, "");
            frequencies.push((prevLength - cNonce.length) / length);
          }

          const entropy = -frequencies.reduce(
            (a, b) => a + b * Math.log2(b),
            0,
          );
          log.info(`  Computed entropy: ${entropy.toFixed(2)} bits`);
          log.info(`  Required entropy: >5 bits`);
          expect(entropy).toBeGreaterThan(5);
          log.info(
            "  ✅ c_nonce has sufficient entropy to prevent guessing attacks",
          );

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      // ============================================================================
      // CREDENTIAL REQUEST TESTS
      // ============================================================================

      test("CI_084: Credential | When all validation checks succeed, Credential Issuer creates a new Credential cryptographically bound to the validated key material and provides it to the Wallet Instance", async () => {
        const log = baseLog.withTag("CI_084");

        log.start(
          "Conformance test: Verifying credential issuance with key binding",
        );

        let testSuccess = false;
        try {
          log.info("→ Checking credential presence...");
          expect(
            credentialResponse.response?.credentials?.length,
          ).toBeGreaterThan(0);
          log.info(
            `  Credentials received: ${credentialResponse.response?.credentials?.length}`,
          );
          log.info("  ✅ Credentials are present");

          log.info("→ Validating credential key pair...");
          const credentialPublicKey =
            credentialResponse.response?.credentialKeyPair?.publicKey;
          expect(credentialPublicKey).toBeDefined();

          if (!credentialPublicKey) {
            log.error("  ❌ Credential public key is undefined");
            testSuccess = false;
            return;
          }
          log.info("  ✅ Credential public key is present");

          log.info("→ Computing JWK Thumbprint of Wallet Instance key...");
          const expectedJkt = await calculateJwkThumbprint(credentialPublicKey);
          log.info(`  Expected JWK Thumbprint: ${expectedJkt}`);

          log.info("→ Verifying cryptographic key binding in credentials...");
          for (const credential of credentialResponse.response?.credentials ??
            []) {
            expect(credential.credential).toBeDefined();

            log.info("  Parsing credential as SD-JWT...");
            const sdJwt = await SDJwt.extractJwt(credential.credential);
            const payload = sdJwt.payload as
              | undefined
              | { cnf?: { jkt?: string; jwk?: object } };

            expect(
              payload?.cnf,
              "SD-JWT credential must contain cnf claim for key binding",
            ).toBeDefined();

            if (payload?.cnf?.jwk) {
              log.info("  Verifying key binding via jwk claim...");
              const credentialJkt = await calculateJwkThumbprint(
                payload.cnf.jwk,
              );
              log.info(`    Credential JWK Thumbprint: ${credentialJkt}`);
              expect(credentialJkt).toBe(expectedJkt);
              log.info(
                "    ✅ Credential is cryptographically bound to Wallet Instance key",
              );
            } else {
              expect.fail(
                "SD-JWT credential cnf claim must contain either jkt or jwk",
              );
            }
          }
          log.info("  ✅ All credentials are properly bound");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      });

      test("CI_118: Credential | (Q)EAA are Issued to a Wallet Instance in SD-JWT VC or mdoc-CBOR data format.", async () => {
        const log = baseLog.withTag("CI_118");

        log.start(
          "Conformance test: Verifying credential format (SD-JWT VC or mdoc-CBOR)",
        );

        let testSuccess = false;
        try {
          log.info("→ Validating credential format...");

          for (const credential of credentialResponse.response?.credentials ??
            []) {
            try {
              log.info("  Attempting to parse as SD-JWT...");
              await SDJwt.extractJwt(credential.credential);
              log.info("  ✅ Credential is in SD-JWT VC format");
              testSuccess = true;
              return;
            } catch {
              log.info("  Not SD-JWT format, trying mdoc-CBOR...");
            }

            try {
              log.info("  Attempting to parse as mdoc-CBOR...");
              parseMdoc(Buffer.from(credential.credential));
              log.info("  ✅ Credential is in mdoc-CBOR format");
              testSuccess = true;
              return;
            } catch {
              log.error(
                "  ❌ Credential is neither SD-JWT VC nor mdoc-CBOR format",
              );
            }
          }

          log.error("  ❌ No credentials found in valid format");
        } finally {
          log.testCompleted(testSuccess);
        }
      });
  });
});
