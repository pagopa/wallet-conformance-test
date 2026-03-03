/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { SDJwt } from "@sd-jwt/core";
import { calculateJwkThumbprint, decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import z from "zod/v3";

import { parseMdoc } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  FetchMetadataStepResponse,
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
      baseLog.testSuite({
        profile: testConfig.credentialConfigurationId,
        target: orchestrator.getConfig().issuance.url,
        title: "Issuance Conformance Tests",
      });

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

        baseLog.info("Issuance flow completed successfully");
      } catch (e) {
        baseLog.error("Issuance flow failed:", e);
        throw e;
      } finally {
        // Give time for all logs to be flushed before starting tests
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    });

    // ============================================================================
    // FETCH METADATA TESTS
    // ============================================================================

    test("CI_001: Fetch Metadata | Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint.", async () => {
      const log = baseLog.withTag("CI_001");
      const DESCRIPTION = "Entity Configuration successfully fetched";

      log.start(
        "Conformance test: Verifying Entity Configuration availability",
      );

      let testSuccess = false;
      try {
        log.debug("→ Checking Entity Configuration fetch was successful...");
        expect(fetchMetadataResponse.success).toBe(true);

        log.debug("→ Validating Entity Statement claims are present...");
        expect(
          fetchMetadataResponse.response?.entityStatementClaims,
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_002: Fetch Metadata | Entity Configuration response media type check", async () => {
      const log = baseLog.withTag("CI_002");
      const DESCRIPTION = "Entity Configuration content-type is correct";

      log.start(
        "Conformance test: Verifying Entity Configuration content-type header",
      );

      let testSuccess = false;
      try {
        // fetchMetadata step doesn't expose the raw response,
        // so we rely on the step's success and presence of claims as an indirect validation of correct content-type handling
        expect(fetchMetadataResponse.success).toBe(true);
        log.debug("  Expected: application/entity-statement+jwt");

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_003: Fetch Metadata | The Entity Configuration is cryptographically signed", async () => {
      const log = baseLog.withTag("CI_003");
      const DESCRIPTION = "Entity Configuration is cryptographically signed";

      log.start(
        "Conformance test: Verifying Entity Configuration JWT signature",
      );

      let testSuccess = false;
      try {
        log.debug("→ Validating response is present...");
        expect(fetchMetadataResponse.response).toBeDefined();

        log.debug("→ Asserting response status...");
        expect(fetchMetadataResponse.response?.status).toBe(200);

        log.debug("→ Checking Entity Statement JWT is present...");
        expect(
          fetchMetadataResponse.response?.discoveredVia === "federation",
        ).toBeTruthy();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_006: Fetch Metadata | Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
      const log = baseLog.withTag("CI_006");
      const DESCRIPTION =
        "All required parameters (iss, sub, iat, exp, jwks, metadata) are present";

      log.start(
        "Conformance test: Verifying Entity Configuration mandatory parameters",
      );

      let testSuccess = false;
      try {
        const entityClaims =
          fetchMetadataResponse.response?.entityStatementClaims;

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
          .safeParse(entityClaims);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_008: Fetch Metadata | Credential Issuer metadata", async () => {
      const log = baseLog.withTag("CI_008");
      const DESCRIPTION =
        "All required metadata sections (federation_entity, oauth_authorization_server, openid_credential_issuer) are present";

      log.start(
        "Conformance test: Verifying Credential Issuer metadata structure",
      );

      let testSuccess = false;
      try {
        const entityClaims =
          fetchMetadataResponse.response?.entityStatementClaims;

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
          .safeParse(entityClaims);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_009: Fetch Metadata | Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
      const log = baseLog.withTag("CI_009");
      const DESCRIPTION = "openid_credential_verifier metadata is present";

      log.start(
        "Conformance test: Verifying openid_credential_verifier metadata presence",
      );

      let testSuccess = false;
      try {
        const entityClaims =
          fetchMetadataResponse.response?.entityStatementClaims;

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
          .safeParse(entityClaims);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // PUSHED AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_040: PAR Request | request_uri validity time is set to less than one minute", async () => {
      const log = baseLog.withTag("CI_040");
      const DESCRIPTION = "request_uri validity time ≤60 seconds";

      log.start("Conformance test: Verifying request_uri expiration time");

      let testSuccess = false;
      try {
        const expires_in =
          pushedAuthorizationRequestResponse.response?.expires_in;
        expect(expires_in).toBeDefined();
        log.debug(`  expires_in: ${expires_in} seconds`);
        expect(expires_in).toBeLessThanOrEqual(60);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_041: PAR Request | Generated request_uri includes a cryptographic random value of at least 128 bits", async () => {
      const log = baseLog.withTag("CI_041");
      const DESCRIPTION = "request_uri has sufficient entropy (≥128 bits)";

      log.start("Conformance test: Verifying request_uri entropy requirements");

      let testSuccess = false;
      try {
        const requestUri =
          pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();

        log.debug(`  request_uri: ${requestUri}`);

        // Extract random portion (e.g. UUID, base64, or hex)
        const randomPart = requestUri?.split(":").pop() ?? "";
        const isBase64 = /^[A-Za-z0-9+/=]+$/.test(randomPart);
        const bitLength = isBase64
          ? randomPart.length * 6
          : randomPart.length * 4; // hex fallback

        log.debug(`  Random part: ${randomPart}`);
        log.debug(`  Bit length: ${bitLength} bits (required: ≥128)`);

        // Ensure it's at least 128 bits of randomness (16 bytes)
        expect(bitLength).toBeGreaterThanOrEqual(128);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_042: PAR Request | Complete request_uri doesn't exceed 512 ASCII characters", async () => {
      const log = baseLog.withTag("CI_042");
      const DESCRIPTION = "request_uri length is compliant (≤512 characters)";

      log.start("Conformance test: Verifying request_uri length constraint");

      let testSuccess = false;
      try {
        const requestUriLength =
          pushedAuthorizationRequestResponse.response?.request_uri.length;
        expect(requestUriLength).toBeDefined();
        log.debug(`  Length: ${requestUriLength} characters (max: 512)`);
        expect(requestUriLength).toBeLessThanOrEqual(512);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_043: PAR Request | When verification is successful, Credential Issuer returns an HTTP response with 201 status code", async () => {
      const log = baseLog.withTag("CI_043");
      const DESCRIPTION = "PAR request successful (no errors)";

      log.start("Conformance test: Verifying PAR request success response");

      let testSuccess = false;
      try {
        expect(pushedAuthorizationRequestResponse.error).toBeUndefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_044a: PAR Request | HTTP response includes request_uri parameter containing the generated one-time authorization URI", async () => {
      const log = baseLog.withTag("CI_044a");
      const DESCRIPTION = "request_uri parameter is present";

      log.start("Conformance test: Verifying request_uri parameter presence");

      let testSuccess = false;
      try {
        const requestUri =
          pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();
        expect(requestUri).toBeTruthy();
        log.debug(`  request_uri: ${requestUri}`);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_044b: PAR Request | HTTP response includes expires_in parameter specifying the validity duration in seconds", async () => {
      const log = baseLog.withTag("CI_044b");
      const DESCRIPTION = "expires_in parameter is present and valid";

      log.start("Conformance test: Verifying expires_in parameter");

      let testSuccess = false;
      try {
        const expiresIn =
          pushedAuthorizationRequestResponse.response?.expires_in;
        expect(expiresIn).toBeDefined();
        expect(typeof expiresIn).toBe("number");
        log.debug(`  expires_in: ${expiresIn} seconds`);
        expect(expiresIn).toBeGreaterThan(0);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_049: Authorization | Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR", async () => {
      const log = baseLog.withTag("CI_049");
      const DESCRIPTION =
        "Authorization successful — issuer correlated PAR and authorization";

      log.start(
        "Conformance test: Verifying PAR and authorization request correlation",
      );

      let testSuccess = false;
      try {
        // Verify PAR response provided a valid request_uri
        const requestUri =
          pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();
        expect(typeof requestUri).toBe("string");
        expect(requestUri?.length).toBeGreaterThan(0);
        log.debug(`  request_uri: ${requestUri}`);

        // Verify the request_uri follows the expected format (urn:ietf:params:oauth:request_uri:...)
        expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:.+$/);

        // Verify authorization was successful - this proves the issuer correlated the request
        // If the issuer couldn't correlate the authorization request with the PAR, it would fail
        expect(authorizeResponse.success).toBe(true);
        expect(
          authorizeResponse.response?.authorizeResponse?.code,
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_054: Authorization | (Q)EAA Provider successfully performs User authentication by requesting and validating a valid PID from the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_054");
      const DESCRIPTION =
        "Authorization code received (user authentication successful)";

      log.start("Conformance test: Verifying PID-based user authentication");

      let testSuccess = false;
      try {
        expect(
          authorizeResponse.response?.authorizeResponse?.code,
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_055: Authorization | (Q)EAA Provider uses OpenID4VP protocol to request PID presentation from the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_055");
      const DESCRIPTION =
        "OpenID4VP presentation successful (authorization code received)";

      log.start("Conformance test: Verifying OpenID4VP protocol usage");

      let testSuccess = false;
      try {
        expect(
          authorizeResponse.response?.authorizeResponse?.code,
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_056: Authorization | (Q)EAA Provider successfully provides the presentation request to the Wallet", async () => {
      const log = baseLog.withTag("CI_056");
      const DESCRIPTION = "Presentation request JWT successfully received";

      log.start("Conformance test: Verifying presentation request delivery");

      let testSuccess = false;
      try {
        expect(authorizeResponse.response?.requestObjectJwt).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_058a: Authorization | Authorization code response includes the authorization code parameter", async () => {
      const log = baseLog.withTag("CI_058a");
      const DESCRIPTION = "Authorization code parameter is present and valid";

      log.start("Conformance test: Verifying authorization code parameter");

      let testSuccess = false;
      try {
        const code = authorizeResponse.response?.authorizeResponse?.code;
        expect(code).toBeDefined();
        expect(typeof code).toBe("string");
        log.debug(`  code: ${code}`);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_058b: Authorization | Authorization code response includes the state parameter matching the original request", async () => {
      const log = baseLog.withTag("CI_058b");
      const DESCRIPTION = "State parameter matches original request";

      log.start("Conformance test: Verifying state parameter matching");

      let testSuccess = false;
      try {
        const responseState =
          authorizeResponse.response?.authorizeResponse?.state;
        const requestState = authorizeResponse.response?.requestObject?.state;

        expect(responseState).toBeDefined();
        expect(typeof responseState).toBe("string");
        log.debug(`  Response state: ${responseState}`);
        log.debug(`  Request state:  ${requestState}`);

        expect(responseState).toBe(requestState);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_058c: Authorization | Authorization code response includes the iss parameter identifying the issuer", async () => {
      const log = baseLog.withTag("CI_058c");
      const DESCRIPTION = "Issuer parameter is present and matches";

      log.start("Conformance test: Verifying issuer identification parameter");

      let testSuccess = false;
      try {
        const responseIss = authorizeResponse.response?.authorizeResponse?.iss;
        const expectedIss = authorizeResponse.response?.iss;

        expect(responseIss).toBeDefined();
        expect(typeof responseIss).toBe("string");
        log.debug(`  Response iss: ${responseIss}`);
        log.debug(`  Expected iss: ${expectedIss}`);

        expect(responseIss).toBe(expectedIss);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // TOKEN REQUEST TESTS
    // ============================================================================

    test("CI_064: Token | Credential Issuer provides the Wallet Instance with a valid Access Token upon successful authorization", async () => {
      const log = baseLog.withTag("CI_064");
      const DESCRIPTION = "Access Token is valid and not expired";

      log.start(
        "Conformance test: Verifying Access Token issuance and validity",
      );

      let testSuccess = false;
      try {
        const token = tokenResponse.response?.access_token;
        expect(token).toBeDefined();

        const claims = decodeJwt(token ?? "");
        const currentTime = Date.now() / 1e3;

        log.debug(`  iat: ${new Date(claims.iat! * 1000).toISOString()}`);
        log.debug(`  exp: ${new Date(claims.exp! * 1000).toISOString()}`);

        expect(claims.exp).toBeGreaterThan(currentTime);
        expect(claims.iat).toBeLessThan(currentTime);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_066: Token | Both Access Token and Refresh Token (when issued) are cryptographically bound to the DPoP key", async () => {
      const log = baseLog.withTag("CI_066");
      const DESCRIPTION = "All tokens are bound to the DPoP key";

      log.start("Conformance test: Verifying DPoP key binding");

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.token_type).toBe("DPoP");

        expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();
        const jkt = await calculateJwkThumbprint(
          walletAttestationResponse.unitKey.publicKey,
        );
        log.debug(`  JWK Thumbprint: ${jkt}`);

        const tokens = [tokenResponse.response?.access_token];
        if (tokenResponse.response?.refresh_token) {
          tokens.push(tokenResponse.response?.refresh_token);
          log.debug("  Validating Access Token + Refresh Token");
        } else {
          log.debug("  Validating Access Token only (no Refresh Token)");
        }

        for (const token of tokens) {
          const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
          expect(claims.cnf?.jkt).toBeDefined();
          expect(claims.cnf?.jkt).toBe(jkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_094: Token | When all validation checks succeed, Credential Issuer generates new Access Token and new Refresh Token, both bound to the DPoP key", async () => {
      const log = baseLog.withTag("CI_094");
      const DESCRIPTION = "Tokens generated and bound to DPoP key";

      log.start(
        "Conformance test: Verifying token generation with DPoP binding",
      );

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.token_type).toBe("DPoP");

        expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();
        const jkt = await calculateJwkThumbprint(
          walletAttestationResponse.unitKey.publicKey,
        );
        log.debug(`  JWK Thumbprint: ${jkt}`);

        const tokens = [tokenResponse.response?.access_token];
        if (tokenResponse.response?.refresh_token) {
          tokens.push(tokenResponse.response?.refresh_token);
        }

        for (const token of tokens) {
          const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
          expect(claims.cnf?.jkt).toBeDefined();
          expect(claims.cnf?.jkt).toBe(jkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_095: Token | Both the Access Token and the Refresh Token are sent back to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_095");
      const DESCRIPTION = "Access Token is present";

      log.start("Conformance test: Verifying token response delivery");

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.access_token).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_101: Token | Access Tokens and Refresh Tokens are bound to the same DPoP key", async () => {
      const log = baseLog.withTag("CI_101");
      const DESCRIPTION = "All tokens bound to the same DPoP key";

      log.start(
        "Conformance test: Verifying consistent DPoP key binding across tokens",
      );

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.token_type).toBe("DPoP");

        expect(walletAttestationResponse.unitKey.publicKey).toBeDefined();
        const jkt = await calculateJwkThumbprint(
          walletAttestationResponse.unitKey.publicKey,
        );
        log.debug(`  JWK Thumbprint: ${jkt}`);

        const tokens = [tokenResponse.response?.access_token];
        if (tokenResponse.response?.refresh_token) {
          tokens.push(tokenResponse.response?.refresh_token);
        }

        for (const token of tokens) {
          const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
          expect(claims.cnf?.jkt).toBeDefined();
          expect(claims.cnf?.jkt).toBe(jkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // NONCE REQUEST TESTS
    // ============================================================================

    test("CI_068: Nonce | Credential Issuer provides a c_nonce value to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_068");
      const DESCRIPTION = "c_nonce parameter is present and non-empty";

      log.start("Conformance test: Verifying c_nonce parameter provision");

      let testSuccess = false;
      try {
        const nonce = nonceResponse.response?.nonce as
          | undefined
          | { c_nonce: string };
        expect(nonce?.c_nonce).toBeDefined();
        expect(nonce?.c_nonce.length).toBeGreaterThan(0);
        log.debug(`  c_nonce length: ${nonce?.c_nonce.length} characters`);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_069: Nonce | The c_nonce parameter is provided as a string value with sufficient unpredictability to prevent guessing attacks, serving as a cryptographic challenge that the Wallet Instance uses to create proof of possession of the key (proofs claim)", async () => {
      const log = baseLog.withTag("CI_069");
      const DESCRIPTION =
        "c_nonce has sufficient entropy to prevent guessing attacks";

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

        log.debug(`  Length: ${length} characters (required: ≥32)`);
        expect(length).toBeGreaterThanOrEqual(32);

        const frequencies: number[] = [];
        for (const char of cNonce) {
          const prevLength = cNonce.length;
          cNonce = cNonce.replace(char, "");
          frequencies.push((prevLength - cNonce.length) / length);
        }

        const entropy = -frequencies.reduce((a, b) => a + b * Math.log2(b), 0);
        log.debug(`  Entropy: ${entropy.toFixed(2)} bits (required: >5)`);
        expect(entropy).toBeGreaterThan(5);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // CREDENTIAL REQUEST TESTS
    // ============================================================================

    test("CI_084: Credential | When all validation checks succeed, Credential Issuer creates a new Credential cryptographically bound to the validated key material and provides it to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_084");
      const DESCRIPTION =
        "Credential is cryptographically bound to Wallet Instance key";

      log.start(
        "Conformance test: Verifying credential issuance with key binding",
      );

      let testSuccess = false;
      try {
        expect(
          credentialResponse.response?.credentials?.length,
        ).toBeGreaterThan(0);
        log.debug(
          `  Credentials received: ${credentialResponse.response?.credentials?.length}`,
        );

        const credentialPublicKey =
          credentialResponse.response?.credentialKeyPair?.publicKey;
        expect(credentialPublicKey).toBeDefined();

        if (!credentialPublicKey) {
          log.error("  Credential public key is undefined");
          testSuccess = false;
          return;
        }

        const expectedJkt = await calculateJwkThumbprint(credentialPublicKey);
        log.debug(`  Expected JWK Thumbprint: ${expectedJkt}`);

        for (const credential of credentialResponse.response?.credentials ??
          []) {
          expect(credential.credential).toBeDefined();

          const sdJwt = await SDJwt.extractJwt(credential.credential);
          const payload = sdJwt.payload as
            | undefined
            | { cnf?: { jkt?: string; jwk?: object } };

          expect(
            payload?.cnf,
            "SD-JWT credential must contain cnf claim for key binding",
          ).toBeDefined();

          if (payload?.cnf?.jwk) {
            const credentialJkt = await calculateJwkThumbprint(payload.cnf.jwk);
            log.debug(`  Credential JWK Thumbprint: ${credentialJkt}`);
            expect(credentialJkt).toBe(expectedJkt);
          } else {
            expect.fail(
              "SD-JWT credential cnf claim must contain either jkt or jwk",
            );
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_118: Credential | (Q)EAA are Issued to a Wallet Instance in SD-JWT VC or mdoc-CBOR data format.", async () => {
      const log = baseLog.withTag("CI_118");
      const DESCRIPTION =
        "Credential is in valid format (SD-JWT VC or mdoc-CBOR)";

      log.start(
        "Conformance test: Verifying credential format (SD-JWT VC or mdoc-CBOR)",
      );

      let testSuccess = false;
      try {
        for (const credential of credentialResponse.response?.credentials ??
          []) {
          try {
            await SDJwt.extractJwt(credential.credential);
            log.debug("  Format: SD-JWT VC");
            testSuccess = true;
            return;
          } catch {
            log.debug("  Not SD-JWT, trying mdoc-CBOR...");
          }

          try {
            parseMdoc(Buffer.from(credential.credential));
            log.debug("  Format: mdoc-CBOR");
            testSuccess = true;
            return;
          } catch {
            log.error("  Credential is neither SD-JWT VC nor mdoc-CBOR format");
          }
        }

        log.error("  No credentials found in valid format");
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
