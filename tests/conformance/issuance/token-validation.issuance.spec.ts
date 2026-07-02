/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { createFreshPop, runAndValidateAuthorize } from "#/helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  AccessTokenRequest,
  createTokenDPoP,
  Jwk,
} from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  UnexpectedStatusCodeError,
} from "@pagopa/io-wallet-utils";
import { beforeAll, describe, expect, test } from "vitest";

import {
  createLogger,
  createQuietLogger,
  loadConfigWithHierarchy,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  CredentialRequestResponse,
  FetchMetadataStepResponse,
  TokenRequestDefaultStep,
  TokenRequestResponse,
} from "@/step/issuance";
import { AttestationResponse, RunThroughTokenContext } from "@/types";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("TokenValidation");

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Token Endpoint Validation`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = createLogger().withTag("Token-Validation");

    let walletAttestationResponse: AttestationResponse;
    let fetchMetadataResponse: FetchMetadataStepResponse;

    let authorizationServer: string;
    let code: string;
    let codeVerifier: string;
    let redirectUri: string;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      ({
        authorizationServer,
        code,
        codeVerifier,
        fetchMetadataResponse,
        redirectUri,
        walletAttestationResponse,
      } = await runAndValidateAuthorize(orchestrator));
    });

    useTestSummary(baseLog, testConfig.name);

    /**
     * Helper to run token request step with overrides
     */
    async function runTokenStep(
      StepClass: typeof TokenRequestDefaultStep,
      accessTokenRequest: AccessTokenRequest,
      fakedPop?: { jwt: string; signerJwk: Jwk },
    ): Promise<TokenRequestResponse> {
      const config = loadConfigWithHierarchy();
      const ioWalletSdkConfig = new IoWalletSdkConfig({
        itWalletSpecsVersion: config.wallet.wallet_version,
      });
      const freshPop = await createFreshPop({
        authorizationServer,
        ioWalletSdkConfig,
        walletAttestationResponse,
      });
      const entityStatementClaims =
        fetchMetadataResponse.response?.entityStatementClaims;
      const step = new StepClass(config, createQuietLogger());
      return await step.run({
        accessTokenEndpoint:
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.token_endpoint,
        accessTokenRequest,
        dpopProof: fakedPop,
        popAttestation: freshPop,
        walletAttestation: walletAttestationResponse,
      });
    }

    // -----------------------------------------------------------------------
    // CI_060 — Authorization Code Issuance
    // -----------------------------------------------------------------------

    test("CI_060: Authorization Code Issuance | Issuer rejects unknown codes (invalid_grant)", async () => {
      const log = baseLog.withTag("CI_060");
      const DESCRIPTION =
        "Issuer correctly rejected unknown authorization code";
      log.start(
        "Conformance test: Verifying unknown authorization codes are rejected",
      );

      let testSuccess = false;
      try {
        const result = await runTokenStep(testConfig.tokenRequestStepClass, {
          code: "unknown-code-123",
          code_verifier: codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        });

        expect(result.success).toBe(false);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_061a — PKCE code_verifier (CRITICAL)
    // -----------------------------------------------------------------------

    test("CI_061a: PKCE code_verifier | Issuer rejects mismatched code_verifier (invalid_grant)", async () => {
      const log = baseLog.withTag("CI_061a");
      const DESCRIPTION = "Issuer correctly rejected mismatched code_verifier";
      log.start("Conformance test: Verifying PKCE code_verifier validation");

      let testSuccess = false;
      try {
        log.info("→ Sending token request with mismatched code_verifier...");
        const result = await runTokenStep(testConfig.tokenRequestStepClass, {
          code,
          code_verifier: "wrong-verifier-123",
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        });

        expect(result.success).toBe(false);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_062 — Redirect URI Matching
    // -----------------------------------------------------------------------

    test("CI_062: Redirect URI Matching | Issuer rejects mismatched redirect_uri (invalid_grant)", async () => {
      const log = baseLog.withTag("CI_062");
      const DESCRIPTION = "Issuer correctly rejected mismatched redirect_uri";
      log.start(
        "Conformance test: Verifying redirect_uri byte-for-byte matching",
      );

      let testSuccess = false;
      try {
        log.info("→ Sending token request with mismatched redirect_uri...");
        const result = await runTokenStep(testConfig.tokenRequestStepClass, {
          code,
          code_verifier: codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: "https://wrong.redirect.uri",
        });

        expect(result.success).toBe(false);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_063 — DPoP Proof JWT
    // -----------------------------------------------------------------------

    test("CI_063: DPoP Proof JWT | Issuer rejects invalid DPoP proof (invalid_dpop_proof)", async () => {
      const log = baseLog.withTag("CI_063");
      const DESCRIPTION = "Issuer correctly rejected invalid DPoP proof";
      log.start("Conformance test: Verifying DPoP proof validation");

      let testSuccess = false;
      try {
        log.info("→ Sending token request with invalid DPoP proof...");

        const { unitKey } = walletAttestationResponse;
        const entityStatementClaims =
          fetchMetadataResponse.response?.entityStatementClaims;
        const invalidDpopRes = await createTokenDPoP({
          callbacks: {
            ...partialCallbacks,
            signJwt: signJwtCallback([unitKey.privateKey]),
          },
          signer: {
            alg: "ES256",
            method: "jwk",
            publicJwk: unitKey.publicKey,
          },
          tokenRequest: {
            method: "GET",
            url: entityStatementClaims.metadata?.oauth_authorization_server
              ?.token_endpoint,
          },
        });

        const result = await runTokenStep(
          testConfig.tokenRequestStepClass,
          {
            code,
            code_verifier: codeVerifier,
            grant_type: "authorization_code",
            redirect_uri: redirectUri,
          },
          invalidDpopRes,
        );

        expect(result.success).toBe(false);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_067 — Token Response HTTP Status Code
    // -----------------------------------------------------------------------

    test("CI_067: Token Response HTTP Status Code | Token endpoint returns HTTP 400 for invalid requests", async () => {
      const log = baseLog.withTag("CI_067");
      const DESCRIPTION =
        "Token endpoint returns HTTP 400 for invalid requests";
      log.start(
        "Conformance test: Verifying token endpoint HTTP status code for invalid requests",
      );

      let testSuccess = false;
      try {
        const result = await runTokenStep(testConfig.tokenRequestStepClass, {
          code: "invalid-code-for-status-check",
          code_verifier: codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        });

        expect(result.success).toBe(false);
        expect(result.error).toBeInstanceOf(UnexpectedStatusCodeError);
        const tokenError = result.error as UnexpectedStatusCodeError;
        expect(
          tokenError.statusCode,
          "Token endpoint must return HTTP 400 for invalid requests",
        ).toBe(400);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_061 — Authorization Code Validity
    // -----------------------------------------------------------------------

    test(
      "CI_061: Authorization Code Validity | Issuer rejects reused code (invalid_grant)",
      { timeout: 6e3 },
      async () => {
        const log = baseLog.withTag("CI_061");
        const DESCRIPTION = "Issuer correctly rejectedd reused code";
        log.start(
          "Conformance test: Verifying authorization code one-time use and expiration",
        );

        let testSuccess = false;
        try {
          const { code, codeVerifier, redirectUri } =
            await runAndValidateAuthorize(orchestrator);

          log.info("→ Performing first (successful) token request...");
          const result1 = await runTokenStep(testConfig.tokenRequestStepClass, {
            code,
            code_verifier: codeVerifier,
            grant_type: "authorization_code",
            redirect_uri: redirectUri,
          });
          expect(result1.success).toBe(true);
          log.info("✅ First request successful");

          await new Promise((resolve) => setTimeout(resolve, 3e3));
          log.info("→ Attempting to reuse the same code...");
          const result2 = await runTokenStep(testConfig.tokenRequestStepClass, {
            code,
            code_verifier: codeVerifier,
            grant_type: "authorization_code",
            redirect_uri: redirectUri,
          });
          expect(result2.success).toBe(false);
          log.info("✅ Reused code rejected");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // -----------------------------------------------------------------------
    // CI_065 — Optional Refresh Token Provision
    // -----------------------------------------------------------------------

    test(
      "CI_065: Refresh Token | If a refresh_token is returned it must have a valid JWT format",
      { timeout: 6e3 },
      async () => {
        const log = baseLog.withTag("CI_065");
        const DESCRIPTION = "Refresh token, when present, has valid JWT format";
        log.start("Conformance test: Verifying optional refresh token format");

        let testSuccess = false;
        try {
          const {
            code,
            codeVerifier: freshCodeVerifier,
            redirectUri: freshRedirectUri,
          } = await runAndValidateAuthorize(orchestrator);

          log.info(
            "→ Performing successful token request to check for refresh_token...",
          );
          const tokenResult = await runTokenStep(
            testConfig.tokenRequestStepClass,
            {
              code,
              code_verifier: freshCodeVerifier,
              grant_type: "authorization_code",
              redirect_uri: freshRedirectUri,
            },
          );
          expect(tokenResult.success).toBe(true);

          const refreshToken = tokenResult.response?.refresh_token;
          if (!refreshToken) {
            log.info(
              "ℹ️  Refresh token not issued (optional per spec — test passes)",
            );
            testSuccess = true;
            return;
          }

          log.info("  Refresh token present, validating JWT format...");
          const parts = refreshToken.split(".");
          expect(
            parts.length,
            "Refresh token must be a JWT with 3 dot-separated parts",
          ).toBe(3);
          for (const part of parts) {
            expect(
              part.length,
              "Each JWT segment must be non-empty",
            ).toBeGreaterThan(0);
            expect(
              /^[A-Za-z0-9_-]+$/.test(part),
              "Each JWT segment must be base64url-encoded",
            ).toBe(true);
          }
          log.info("✅ Refresh token has valid JWT format");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // -----------------------------------------------------------------------
    // CI_070 — C_nonce Reusability and Renewal
    // -----------------------------------------------------------------------

    test(
      "CI_070: C_nonce | Server issues distinct nonces and credential requests with fresh c_nonce must succeed",
      { timeout: 20e3 },
      async () => {
        const log = baseLog.withTag("CI_070");
        const DESCRIPTION =
          "C_nonce reusability and renewal behaviour verified";
        log.start(
          "Conformance test: Verifying c_nonce reusability and renewal",
        );

        let testSuccess = false;
        try {
          log.info("→ Running full flow to obtain token context...");
          const freshOrchestrator = new WalletIssuanceOrchestratorFlow(
            testConfig,
          );
          const tokenCtx: RunThroughTokenContext =
            await freshOrchestrator.runThroughToken();
          const entityStatementClaims =
            tokenCtx.fetchMetadataResponse.response?.entityStatementClaims;

          const rawNonceEndpoint =
            entityStatementClaims?.metadata?.openid_credential_issuer
              ?.nonce_endpoint;
          if (!rawNonceEndpoint)
            throw new Error("Issuer metadata does not contain nonce_endpoint");
          const nonceEndpoint: string = rawNonceEndpoint;

          const rawCredentialEndpoint =
            entityStatementClaims?.metadata?.openid_credential_issuer
              ?.credential_endpoint;
          if (!rawCredentialEndpoint)
            throw new Error(
              "Issuer metadata does not contain credential_endpoint",
            );
          const credentialEndpoint: string = rawCredentialEndpoint;

          const rawAccessToken = tokenCtx.tokenResponse.response?.access_token;
          if (!rawAccessToken)
            throw new Error("Token step did not return access_token");
          const accessToken: string = rawAccessToken;

          const config = loadConfigWithHierarchy();

          async function fetchNonce(): Promise<string> {
            const nonceStep = new testConfig.nonceRequestStepClass(
              config,
              createQuietLogger(),
            );
            const nonceResp = await nonceStep.run({ nonceEndpoint });
            const nonce = nonceResp.response?.nonce as
              | undefined
              | { c_nonce: string };
            if (!nonce?.c_nonce)
              throw new Error("Failed to obtain c_nonce from nonce endpoint");
            return nonce.c_nonce;
          }

          async function runCredentialWithNonce(
            nonce: string,
          ): Promise<CredentialRequestResponse> {
            const step = new testConfig.credentialRequestStepClass(
              config,
              createQuietLogger(),
            );
            return step.run({
              accessToken,
              clientId:
                tokenCtx.walletAttestationResponse.unitKey.publicKey.kid,
              credentialIdentifier: testConfig.credentialConfigurationId,
              credentialIssuer: tokenCtx.credentialIssuer,
              credentialRequestEndpoint: credentialEndpoint,
              dPoPKey: tokenCtx.dPoPKey,
              nonce,
              walletAttestation: tokenCtx.walletAttestationResponse,
            });
          }

          log.info("→ Fetching first c_nonce...");
          const nonce1 = await fetchNonce();
          log.debug(`  nonce1 length: ${nonce1.length}`);

          log.info("→ First credential request with nonce1...");
          const result1 = await runCredentialWithNonce(nonce1);
          expect(
            result1.success,
            "First credential request with fresh c_nonce must succeed",
          ).toBe(true);
          log.info("✅ First credential request succeeded");

          log.info("→ Second credential request reusing nonce1...");
          const result2 = await runCredentialWithNonce(nonce1);
          if (result2.success) {
            log.info(
              "ℹ️  Server allows c_nonce reuse (nonce remains valid after first use)",
            );
          } else {
            log.info(
              "ℹ️  Server enforces single-use c_nonce (nonce invalidated after first use)",
            );
          }

          log.info("→ Fetching second c_nonce...");
          const nonce2 = await fetchNonce();
          log.debug(`  nonce2 length: ${nonce2.length}`);
          expect(
            nonce2,
            "Server must generate distinct c_nonce values on each request",
          ).not.toBe(nonce1);

          log.info("→ Credential request with renewed nonce2...");
          const result3 = await runCredentialWithNonce(nonce2);
          expect(
            result3.success,
            "Credential request with a fresh c_nonce must succeed",
          ).toBe(true);
          log.info("✅ Credential request with renewed c_nonce succeeded");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    // -----------------------------------------------------------------------
    // CI_098 — TLS-Protected Refresh Token Transmission
    // -----------------------------------------------------------------------

    test(
      "CI_098: TLS | Refresh token is transmitted only over a TLS-protected channel",
      { timeout: 6e3 },
      async () => {
        const log = baseLog.withTag("CI_098");
        const DESCRIPTION = "Token endpoint is TLS-protected (HTTPS)";
        log.start(
          "Conformance test: Verifying TLS protection of token endpoint",
        );

        let testSuccess = false;
        try {
          const entityStatementClaims =
            fetchMetadataResponse.response?.entityStatementClaims;
          const tokenEndpoint =
            entityStatementClaims?.metadata?.oauth_authorization_server
              ?.token_endpoint;

          log.debug(`  token_endpoint: ${tokenEndpoint}`);
          expect(
            tokenEndpoint,
            "Token endpoint must use HTTPS to protect refresh token transmission",
          ).toMatch(/^https:\/\//);

          const {
            code,
            codeVerifier: freshCodeVerifier,
            redirectUri: freshRedirectUri,
          } = await runAndValidateAuthorize(orchestrator);
          const tokenResult = await runTokenStep(
            testConfig.tokenRequestStepClass,
            {
              code,
              code_verifier: freshCodeVerifier,
              grant_type: "authorization_code",
              redirect_uri: freshRedirectUri,
            },
          );
          expect(tokenResult.success).toBe(true);

          if (tokenResult.response?.refresh_token) {
            log.info(
              "  Refresh token received over TLS-protected HTTPS endpoint ✅",
            );
          } else {
            log.info(
              "  No refresh token issued; token endpoint TLS protection confirmed ✅",
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );
  });
});
