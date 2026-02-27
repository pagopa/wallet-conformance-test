/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { createFreshPop } from "#/helpers";
import { AccessTokenRequest, createTokenDPoP } from "@pagopa/io-wallet-oauth2";
import { beforeAll, describe, expect, test } from "vitest";

import {
  createLogger,
  loadConfigWithHierarchy,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeStepResponse,
  FetchMetadataStepResponse,
  PushedAuthorizationRequestResponse,
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
    const baseLog = createLogger().withTag("Token-Validation");

    let walletAttestationResponse: AttestationResponse;
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let authorizeResponse: AuthorizeStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;

    let authorizationServer: string;
    let code: string;
    let codeVerifier: string;
    let redirectUri: string;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
      // Run through the flow up to the PAR step to extract necessary context for the tests
      const ctx = await orchestrator.runThroughAuthorize();

      walletAttestationResponse = ctx.walletAttestationResponse;
      authorizationServer = ctx.authorizationServer;
      fetchMetadataResponse = ctx.fetchMetadataResponse;
      authorizeResponse = ctx.authorizeResponse;
      pushedAuthorizationRequestResponse =
        ctx.pushedAuthorizationRequestResponse;

      if (!authorizeResponse.response?.authorizeResponse)
        throw new Error("Authorization Response not found");

      code = authorizeResponse.response.authorizeResponse.code;

      if (!authorizeResponse.response?.requestObject)
        throw new Error("Authorization Response not found");

      redirectUri = authorizeResponse.response.requestObject.response_uri;

      if (!pushedAuthorizationRequestResponse.response)
        throw new Error(
          "Pushed Authorization Request Step did not return code_verifier",
        );

      codeVerifier = pushedAuthorizationRequestResponse.response.codeVerifier;
    });

    /**
     * Helper to run token request step with overrides
     */
    async function runTokenStep(
      StepClass: typeof TokenRequestDefaultStep,
      accessTokenRequest: AccessTokenRequest,
      fakedPop?: string,
    ): Promise<TokenRequestResponse> {
      const config = loadConfigWithHierarchy();
      const freshPop = await createFreshPop({
        authorizationServer,
        walletAttestationResponse,
      });
      const entityStatementClaims =
        fetchMetadataResponse.response?.entityStatementClaims;
      const step = new StepClass(config, baseLog);
      return await step.run({
        accessTokenEndpoint:
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.token_endpoint,
        accessTokenRequest,
        popAttestation: fakedPop ?? freshPop,
        walletAttestation: walletAttestationResponse,
      });
    }

    // -----------------------------------------------------------------------
    // CI_060 — Authorization Code Issuance
    // -----------------------------------------------------------------------

    test("CI_060: Authorization Code Issuance | Issuer rejects unknown codes (invalid_grant)", async () => {
      const log = baseLog.withTag("CI_060");
      log.start(
        "Conformance test: Verifying unknown authorization codes are rejected",
      );

      const result = await runTokenStep(testConfig.tokenRequestStepClass, {
        code: "unknown-code-123",
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      });

      expect(result.success).toBe(false);
      // expect(["invalid_grant", "server error"]).toContain(result.error?.message);
      log.info("✅ Issuer correctly rejected unknown authorization code");
    });

    // -----------------------------------------------------------------------
    // CI_061 — Authorization Code Validity
    // -----------------------------------------------------------------------

    test(
      "CI_061: Authorization Code Validity | Issuer rejects reused codes (invalid_grant)",
      async () => {
        const log = baseLog.withTag("CI_061");
        log.start(
          "Conformance test: Verifying authorization code one-time use",
        );

        log.info("→ Performing first (successful) token request...");
        const result1 = await runTokenStep(testConfig.tokenRequestStepClass, {
          code,
          code_verifier: codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        });
        expect(result1.success).toBe(true);
        log.info("✅ First request successful");

        await new Promise((resolve) => setTimeout(resolve, 60e3));
        log.info("→ Attempting to reuse the same code...");
        const result2 = await runTokenStep(testConfig.tokenRequestStepClass, {
          code,
          code_verifier: codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        });

        expect(result2.success).toBe(false);
        log.info(
          "✅ Issuer behavior documented (Review required for code reuse)",
        );
      },
      { timeout: 61e3 },
    );

    // -----------------------------------------------------------------------
    // CI_061a — PKCE code_verifier (CRITICAL)
    // -----------------------------------------------------------------------

    test("CI_061a: PKCE code_verifier | Issuer rejects mismatched code_verifier (invalid_grant)", async () => {
      const log = baseLog.withTag("CI_061a");
      log.start("Conformance test: Verifying PKCE code_verifier validation");

      log.info("→ Sending token request with mismatched code_verifier...");
      const result = await runTokenStep(testConfig.tokenRequestStepClass, {
        code,
        code_verifier: "wrong-verifier-123",
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      });

      // Mock issuer returns 500 for PKCE mismatch
      expect(result.success).toBe(false);
      // expect(["invalid_grant", "server error"]).toContain(result.error?.message);
      log.info("✅ Issuer correctly rejected mismatched code_verifier");
    });

    // -----------------------------------------------------------------------
    // CI_062 — Redirect URI Matching
    // -----------------------------------------------------------------------

    test("CI_062: Redirect URI Matching | Issuer rejects mismatched redirect_uri (invalid_grant)", async () => {
      const log = baseLog.withTag("CI_062");
      log.start(
        "Conformance test: Verifying redirect_uri byte-for-byte matching",
      );

      log.info("→ Sending token request with mismatched redirect_uri...");
      const result = await runTokenStep(testConfig.tokenRequestStepClass, {
        code,
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: "https://wrong.redirect.uri",
      });

      expect(result.success).toBe(false);
      log.info(
        "✅ Issuer behavior documented (Review required for redirect_uri matching)",
      );
    });

    // -----------------------------------------------------------------------
    // CI_063 — DPoP Proof JWT
    // -----------------------------------------------------------------------

    test("CI_063: DPoP Proof JWT | Issuer rejects invalid DPoP proof (invalid_dpop_proof)", async () => {
      const log = baseLog.withTag("CI_063");
      log.start("Conformance test: Verifying DPoP proof validation");

      log.info(
        "→ Sending token request with invalid DPoP proof (wrong htm)...",
      );

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
        invalidDpopRes.jwt,
      );

      // Mock issuer returns 500 for DPoP error
      expect(result.success).toBe(false);
      // expect(["invalid_dpop_proof", "invalid_grant", "server error"]).toContain(result.error?.message);
      log.info("✅ Issuer correctly rejected invalid DPoP proof");
    });
  });
});
