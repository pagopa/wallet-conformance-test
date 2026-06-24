import type { ImmediateCredentialResponse } from "@pagopa/io-wallet-oid4vci";

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertDeferredIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeAll, describe, expect, test } from "vitest";

import type { DeferredCredentialRequestResponse } from "@/step/issuance";

import { loadConfigWithHierarchy } from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";

const testConfigs = await defineIssuanceTest("DeferredEndpointIssuance");

const isV1_0 = new IoWalletSdkConfig({
  itWalletSpecsVersion: loadConfigWithHierarchy().wallet.wallet_version,
}).isVersion(ItWalletSpecsVersion.V1_0);

testConfigs.forEach((testConfig) => {
  describe.skipIf(isV1_0)(
    `[${testConfig.name}] Deferred Endpoint Issuance`,
    () => {
      const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
      const baseLog = orchestrator.getLog();

      let deferredCredentialResponse: DeferredCredentialRequestResponse;

      beforeAll(async () => {
        try {
          const result = await orchestrator.deferred();
          assertDeferredIssuanceFlowSuccess(result);

          deferredCredentialResponse = result.deferredCredentialResponse;

          baseLog.info("Deferred issuance flow completed successfully");
        } catch (e) {
          baseLog.error(e);
          throw e;
        } finally {
          // Give time for all logs to be flushed before starting tests
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      });

      useTestSummary(baseLog, testConfig.name);

      test("CI_088a: Deferred Endpoint Issuance | Access Token allows access to Deferred endpoint for obtaining new Digital Credentials after interval or readiness notification", async () => {
        const log = baseLog.withTag("CI_088a");
        const DESCRIPTION =
          "Access token successfully used for Deferred endpoint and credential obtained";

        let testSuccess = false;
        try {
          expect(
            deferredCredentialResponse.success,
            "Deferred credential request step failed",
          ).toBe(true);
          expect(
            deferredCredentialResponse.response,
            "Deferred credential response body is undefined",
          ).toBeDefined();

          const response = deferredCredentialResponse.response;

          expect(
            response && "credentials" in response,
            "Deferred credential response does not contain credentials (issuer may have returned a pending transaction_id instead of a credential)",
          ).toBe(true);

          // Safe cast: we have verified 'credentials' is present via the expect above
          const immediateResponse = response as ImmediateCredentialResponse;

          expect(
            immediateResponse.credentials.length,
            "Deferred credential response contains no credentials",
          ).toBeGreaterThan(0);
          expect(
            immediateResponse.credentials[0]?.credential,
            "First deferred credential value is undefined",
          ).toBeDefined();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      });
    },
  );
});
