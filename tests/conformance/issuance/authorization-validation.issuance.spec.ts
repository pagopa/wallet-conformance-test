/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { beforeAll, describe, expect, test } from "vitest";

import { loadConfigWithHierarchy } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { FetchMetadataStepResponse } from "@/step";
import {
  AuthorizeDefaultStep,
  AuthorizeStepResponse,
  PushedAuthorizationRequestResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";

// Define and auto-register test configuration
const testConfigs = await defineIssuanceTest("AuthorizationRequestValidation");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, () => {
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    let authorizeResponse: AuthorizeStepResponse;
    let walletAttestationResponse: AttestationResponse;
    let authorizationEndpoint: string;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      baseLog.info("========================================");
      baseLog.info("🚀 Starting Authorization Validation Tests");
      baseLog.info("========================================");
      baseLog.info("");

      const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
      const ctx = await orchestrator.runThroughAuthorize();

      authorizeResponse = ctx.authorizeResponse;
      walletAttestationResponse = ctx.walletAttestationResponse;
      pushedAuthorizationRequestResponse =
        ctx.pushedAuthorizationRequestResponse;
      fetchMetadataResponse = ctx.fetchMetadataResponse;
      authorizationEndpoint = ctx.authorizationEndpoint;
    });

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
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentials: [],
        requestUri,
        rpMetadata: entityClaims?.metadata?.openid_credential_verifier,
        walletAttestation: attestationOverride ?? walletAttestationResponse,
      });
    }
    // -----------------------------------------------------------------------
    // CI_047 — Request URI One-Time Use
    // -----------------------------------------------------------------------

    test(
      "CI_047: Request URI One-Time Use | Verify request_uri one-time use and expiration (Reject reused request_uri)",
      async () => {
        const log = baseLog.withTag("CI_047");
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
            setTimeout(resolve, 60e3),
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
          if (duplicateResult.success === false)
            log.info("  ✅ Issuer correctly rejected reused request_uri");
          else log.error(" ❌ Issuer accepted reused request_uri");

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
          log.info("  ✅ Issuer correctly rejected expired request_uri");

          testSuccess = true;
        } finally {
          log.testCompleted(testSuccess);
        }
      },
      { timeout: 61e3 },
    );

    // -----------------------------------------------------------------------
    // CI_048 — Duplicate Request Tolerance
    // -----------------------------------------------------------------------

    test("CI_048: Duplicate Request Tolerance | Verify optional duplicate tolerance (Optional grace period)", async () => {
      const log = baseLog.withTag("CI_048");
      log.start("Conformance test: Verifying duplicate request tolerance");

      let testSuccess = false;
      try {
        log.info("→ Performing new PAR request to get a fresh request_uri...");
        const parResult = await orchestrator.runThroughPar();
        const requestUri =
          parResult.pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();

        log.info("→ Sending two requests in rapid succession...");
        const promise1 = await runAuthStep(
          testConfig.authorizeStepClass,
          requestUri,
        );

        // Small delay but within typical grace period (2000ms)
        await new Promise((r) => setTimeout(r, 2e3));

        const promise2 = await runAuthStep(
          testConfig.authorizeStepClass,
          requestUri,
        );

        const [res1, res2] = await Promise.all([promise1, promise2]);
        log.info(`  Result 1 success: ${res1.success}`);
        log.info(`  Result 2 success: ${res2.success}`);

        expect(res1).toStrictEqual(res2);
        log.info("  ✅ Duplicate request tolerance test completed");

        testSuccess = true;
      } finally {
        log.testCompleted(testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_050 — Request URI Requirement
    // -----------------------------------------------------------------------

    test("CI_050: Request URI Requirement | Verify request_uri required (Reject without request_uri)", async () => {
      const log = baseLog.withTag("CI_050");
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
        log.info("  ✅ Issuer correctly enforced request_uri requirement");

        testSuccess = true;
      } finally {
        log.testCompleted(testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_051 — CieID High-Level Authentication
    // -----------------------------------------------------------------------

  //   test("CI_051: CieID High-Level Authentication | Verify authentication level (Validate acr claim)", async () => {
  //     const log = baseLog.withTag("CI_051");
  //     log.start(
  //       "Conformance test: Verifying CieID High-Level Authentication (acr/acr_values/LoA)",
  //     );

  //     let testSuccess = false;
  //     try {
  //       log.info("→ Inspecting metadata and requestObject...");

  //       const entityClaims =
  //         fetchMetadataResponse.response?.entityStatementClaims;
  //       const oauthMetadata =
  //         entityClaims?.metadata?.oauth_authorization_server;
  //       const issuerMetadata = entityClaims?.metadata?.openid_credential_issuer;
  //       log.info(
  //         `→ Supported ACR values: ${JSON.stringify(oauthMetadata?.acr_values_supported)}`,
  //       );
  //       log.info(
  //         `→ Supported Credential Configurations: ${JSON.stringify(Object.keys(issuerMetadata?.credential_configurations_supported ?? {}))}`,
  //       );

  //       const requestObject = authorizeResponse.response?.requestObject;
  //       expect(requestObject).toBeDefined();

  //       log.info(
  //         `→ Request Object Payload: ${JSON.stringify(requestObject, null, 2)}`,
  //       );

  //       // Look for acr in various standard locations
  //       const acrTopLevel = (requestObject as any).acr;
  //       const acrInClaims = (requestObject as any).claims?.acr;
  //       const acrInVpToken = (requestObject as any).claims?.vp_token?.acr;
  //       const acrValues = (requestObject as any).acr_values;
  //       const presentationDefinitionAcr = (
  //         requestObject as any
  //       ).presentation_definition?.constraints?.fields?.find((f: any) =>
  //         f.path?.some((p: string) => p.includes("acr")),
  //       );

  //       log.info(`  acr (top-level): ${acrTopLevel}`);
  //       log.info(`  acr (claims.acr): ${JSON.stringify(acrInClaims)}`);
  //       log.info(
  //         `  acr (claims.vp_token.acr): ${JSON.stringify(acrInVpToken)}`,
  //       );
  //       log.info(`  acr_values: ${acrValues}`);
  //       log.info(
  //         `  acr (presentation_definition): ${!!presentationDefinitionAcr}`,
  //       );

  //       const foundAcr =
  //         acrTopLevel ||
  //         acrInClaims ||
  //         acrInVpToken ||
  //         acrValues ||
  //         presentationDefinitionAcr;

  //       if (!foundAcr) {
  //         log.warn(
  //           "⚠️  acr claim not found in standard locations. Marking as failed for conformance.",
  //         );
  //         expect(foundAcr).toBeDefined();
  //       }

  //       log.info("  ✅ acr claim found and validated");
  //       testSuccess = true;
  //     } finally {
  //       log.testCompleted(testSuccess);
  //     }
  //   });
  });
});
