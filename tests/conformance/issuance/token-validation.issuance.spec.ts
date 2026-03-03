/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { createFreshPop, runAndValidateAuthorize } from "#/helpers";
import {
  AccessTokenRequest,
  createTokenDPoP,
  Jwk,
} from "@pagopa/io-wallet-oauth2";
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
  FetchMetadataStepResponse,
  TokenRequestDefaultStep,
  TokenRequestResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("HappyFlowIssuance");

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
      baseLog.testSuite({
        profile: testConfig.credentialConfigurationId,
        target: orchestrator.getConfig().issuance.url,
        title: "Token Endpoint Validation Tests",
      });

      ({
        authorizationServer,
        code,
        codeVerifier,
        fetchMetadataResponse,
        redirectUri,
        walletAttestationResponse,
      } = await runAndValidateAuthorize(orchestrator));
    });

    /**
     * Helper to run token request step with overrides
     */
    async function runTokenStep(
      StepClass: typeof TokenRequestDefaultStep,
      accessTokenRequest: AccessTokenRequest,
      fakedPop?: { jwt: string; signerJwk: Jwk },
    ): Promise<TokenRequestResponse> {
      const config = loadConfigWithHierarchy();
      const freshPop = await createFreshPop({
        authorizationServer,
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
        "✅ Issuer correctly rejected unknown authorization code";
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
      const DESCRIPTION =
        "✅ Issuer correctly rejected mismatched code_verifier";
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
      const DESCRIPTION = "✅ Issuer behavior documented";
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
      const DESCRIPTION = "✅ Issuer correctly rejected invalid DPoP proof";
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
    // CI_061 — Authorization Code Validity
    // -----------------------------------------------------------------------

    test(
      "CI_061: Authorization Code Validity | Issuer rejects reused and expired codes (invalid_grant)",
      async () => {
        const log = baseLog.withTag("CI_061");
        const DESCRIPTION = "✅ Issuer behavior documented";
        log.start(
          "Conformance test: Verifying authorization code one-time use and expiration",
        );

        let testSuccess = false;
        try {
          const {
            code: expiredCode,
            codeVerifier: expiredCodeVerifier,
            redirectUri: expiredRedirectUri,
          } = await runAndValidateAuthorize(orchestrator);
          const sleep = new Promise((resolve) => setTimeout(resolve, 60e3));

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

          await sleep;
          const expired = await runTokenStep(testConfig.tokenRequestStepClass, {
            code: expiredCode,
            code_verifier: expiredCodeVerifier,
            grant_type: "authorization_code",
            redirect_uri: expiredRedirectUri,
          });
          expect(expired.success).toBe(false);
          log.info("✅ Expired code rejected");
          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
      { timeout: 61e3 },
    );
  });
});
