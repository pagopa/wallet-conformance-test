import { defineIssuanceTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import { loadConfigWithHierarchy } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeDefaultStep,
  AuthorizeStepResponse,
  FetchMetadataStepResponse,
  PushedAuthorizationRequestResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";

// Define and auto-register test configuration
const testConfigs = await defineIssuanceTest("AuthorizationRequestValidation");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, () => {
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    let walletAttestationResponse: AttestationResponse;
    let authorizationEndpoint: string;
    let credentialIssuer: string;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      baseLog.testSuite({
        profile: testConfig.credentialConfigurationId,
        target: orchestrator.getConfig().issuance.url,
        title: "Issuer Authorization Validation Tests",
      });

      const ctx = await orchestrator.runThroughAuthorize();

      credentialIssuer = ctx.credentialIssuer;
      walletAttestationResponse = ctx.walletAttestationResponse;
      pushedAuthorizationRequestResponse =
        ctx.pushedAuthorizationRequestResponse;
      fetchMetadataResponse = ctx.fetchMetadataResponse;
      authorizationEndpoint = ctx.authorizationEndpoint;
    });

    useTestSummary(baseLog, testConfig.name);

    async function runAuthStep(
      StepClass: typeof AuthorizeDefaultStep,
      requestUri?: string,
      attestationOverride?: Omit<AttestationResponse, "created">,
    ): Promise<AuthorizeStepResponse> {
      const config = loadConfigWithHierarchy();

      // Get the real authorization endpoint from metadata
      const entityClaims =
        fetchMetadataResponse.response?.entityStatementClaims;

      const step = new StepClass(config, baseLog);
      return step.run({
        authorizationEndpoint,
        baseUrl: credentialIssuer,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentials: [],
        ioWalletSdkConfig: new IoWalletSdkConfig({
          itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
        }),
        requestUri: requestUri ?? "",
        rpMetadata: entityClaims?.metadata?.openid_credential_verifier,
        walletAttestation: attestationOverride ?? walletAttestationResponse,
      });
    }

    // -----------------------------------------------------------------------
    // CI_048 — Duplicate Request Tolerance
    // -----------------------------------------------------------------------

    test("CI_048: Duplicate Request Tolerance | Verify optional duplicate tolerance (Optional grace period)", async () => {
      const log = baseLog.withTag("CI_048");
      const DESCRIPTION = "✅ Duplicate request tolerance test completed";
      log.start("Conformance test: Verifying duplicate request tolerance");

      let testSuccess = false;
      try {
        log.info("→ Performing new PAR request to get a fresh request_uri...");
        const parResult = await orchestrator.runThroughPar();
        const requestUri =
          parResult.pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();

        log.info("→ Sending two requests in rapid succession...");
        const promise1 = runAuthStep(testConfig.authorizeStepClass, requestUri);

        // Small delay but within typical grace period (2000ms)
        await new Promise((r) => setTimeout(r, 2e3));

        const promise2 = runAuthStep(testConfig.authorizeStepClass, requestUri);

        const [res1, res2] = await Promise.all([promise1, promise2]);
        log.info(`  Result 1 success: ${res1.success}`);
        log.info(`  Result 2 success: ${res2.success}`);

        expect(res1.success).toBe(res2.success);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_050 — Request URI Requirement
    // -----------------------------------------------------------------------

    test("CI_050: Request URI Requirement | Verify request_uri required", async () => {
      const log = baseLog.withTag("CI_050");
      const DESCRIPTION =
        "✅ Issuer correctly enforced request_uri requirement";
      log.start(
        "Conformance test: Verifying request_uri is required (PAR-only flow)",
      );

      let testSuccess = false;
      try {
        log.info("→ Sending authorization request without request_uri...");

        const result = await runAuthStep(testConfig.authorizeStepClass);

        log.info(
          "→ Validating issuer rejected the request missing request_uri...",
        );
        expect(result.success).toBe(false);
        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_047 — Request URI One-Time Use
    // -----------------------------------------------------------------------

    test(
      "CI_047: Request URI One-Time Use | Verify request_uri one-time use and expiration (Reject reused request_uri)",
      async () => {
        const log = baseLog.withTag("CI_047");
        const DESCRIPTION = "✅ Issuer correctly rejected expired request_uri";
        log.start("Conformance test: Verifying request_uri one-time use");

        let testSuccess = false;
        try {
          const requestUri =
            pushedAuthorizationRequestResponse.response?.request_uri;
          expect(requestUri).toBeDefined();

          log.info(
            "→ Performing new PAR request to get a fresh request_uri...",
          );
          const { pushedAuthorizationRequestResponse: parResponse } =
            await orchestrator.runThroughPar();
          const expiration = new Promise((resolve) =>
            setTimeout(resolve, parResponse.response?.expires_in ?? 60e3),
          );

          //Wait for expiration of optional grace period
          await new Promise((resolve) => setTimeout(resolve, 3e3));
          log.info(`→ Reusing request_uri: ${requestUri}`);
          log.info(
            "→ Attempting second authorization request with the same request_uri...",
          );
          const duplicateResult = await runAuthStep(
            testConfig.authorizeStepClass,
            requestUri,
          );

          log.info("→ Validating issuer rejected the reused request_uri...");
          expect(duplicateResult.success).toBe(false);

          log.info(`→ Wait for expiration of request_uri: ${requestUri}`);
          await expiration;

          log.info(
            "→ Attempting first authorization request with the expired request_uri...",
          );
          const expiredResult = await runAuthStep(
            testConfig.authorizeStepClass,
            parResponse.response?.request_uri,
          );

          log.info("→ Validating issuer rejected the expired request_uri...");
          expect(expiredResult.success).toBe(false);
          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
      { timeout: 120e3 },
    );
  });
});
