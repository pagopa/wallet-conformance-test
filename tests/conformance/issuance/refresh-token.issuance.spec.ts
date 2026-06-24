import { defineIssuanceTest } from "#/config/test-metadata";
import { assertReissuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import {
  withInvalidClientAttestationPop,
  withInvalidRefreshTokenDPoP,
  withRefreshTokenDPoPSignedByWrongKey,
} from "#/helpers/refresh-token-validation-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import type { CredentialRequestResponse } from "@/step/issuance";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";

const testConfigs = await defineIssuanceTest("RefreshTokenIssuance");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Refresh Token Issuance`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let credentialResponse: CredentialRequestResponse;

    beforeAll(async () => {
      try {
        const result = await orchestrator.reissuance();
        assertReissuanceFlowSuccess(result);

        credentialResponse = result.credentialResponse;

        baseLog.info("Re-issuance flow completed successfully");
      } catch (e) {
        baseLog.error(e);
        throw e;
      } finally {
        // Give time for all logs to be flushed before starting tests
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    });

    useTestSummary(baseLog, testConfig.name);

    test("CI_088: Refresh Token Issuance | Access Token obtained through a Refresh Token flow is successfully used for Credential endpoint", async () => {
      const log = baseLog.withTag("CI_088");
      const DESCRIPTION =
        "Access token obtained through refresh token flow successfully used for Credential endpoint";

      let testSuccess = false;
      try {
        expect(
          credentialResponse.success,
          "Credential request step failed",
        ).toBe(true);
        expect(
          credentialResponse.response,
          "Credential response body is undefined",
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_091: OAuth-Client-Attestation-PoP Validation | Issuer rejects a refresh-token reissuance request with invalid OAuth-Client-Attestation-PoP", async () => {
      const log = baseLog.withTag("CI_091");
      const DESCRIPTION =
        "Issuer correctly rejected refresh-token reissuance with invalid OAuth-Client-Attestation-PoP";

      let testSuccess = false;
      try {
        const negativeOrchestrator = new WalletIssuanceOrchestratorFlow({
          ...testConfig,
          tokenRequestStepClass: withInvalidClientAttestationPop(
            testConfig.tokenRequestStepClass,
          ),
        });

        const result = await negativeOrchestrator.reissuance();

        expect(
          result.success,
          "Re-issuance flow succeeded despite invalid OAuth-Client-Attestation-PoP",
        ).toBe(false);
        expect(
          result.tokenResponse?.success,
          "Token request did not fail; rejection may have happened outside token endpoint validation",
        ).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_092: DPoP Proof JWT | Issuer rejects a refresh-token reissuance request with invalid DPoP proof", async () => {
      const log = baseLog.withTag("CI_092");
      const DESCRIPTION =
        "Issuer correctly rejected refresh-token reissuance with invalid DPoP proof";

      let testSuccess = false;
      try {
        const negativeOrchestrator = new WalletIssuanceOrchestratorFlow({
          ...testConfig,
          tokenRequestStepClass: withInvalidRefreshTokenDPoP(
            testConfig.tokenRequestStepClass,
          ),
        });

        const result = await negativeOrchestrator.reissuance();

        expect(
          result.success,
          "Re-issuance flow succeeded despite invalid DPoP proof",
        ).toBe(false);
        expect(
          result.tokenResponse?.success,
          "Token request did not fail; rejection may have happened outside token endpoint DPoP validation",
        ).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_093: Refresh Token Binding | Issuer rejects a refresh-token reissuance request when DPoP proof key differs from the Refresh Token binding key", async () => {
      const log = baseLog.withTag("CI_093");
      const DESCRIPTION =
        "Issuer correctly rejected refresh-token reissuance with DPoP key not bound to the Refresh Token";

      let testSuccess = false;
      try {
        const negativeOrchestrator = new WalletIssuanceOrchestratorFlow({
          ...testConfig,
          tokenRequestStepClass: withRefreshTokenDPoPSignedByWrongKey(
            testConfig.tokenRequestStepClass,
          ),
        });

        const result = await negativeOrchestrator.reissuance();

        expect(
          result.success,
          "Re-issuance flow succeeded despite DPoP key not matching Refresh Token binding",
        ).toBe(false);
        expect(
          result.tokenResponse?.success,
          "Token request did not fail; rejection may have happened outside refresh-token DPoP binding validation",
        ).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
