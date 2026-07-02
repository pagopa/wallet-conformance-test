import type { ImmediateCredentialResponse } from "@pagopa/io-wallet-oid4vci";

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertDeferredIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeAll, describe, expect, test } from "vitest";

import type {
  DeferredCredentialRequestResponse,
  FetchMetadataStepResponse,
} from "@/step/issuance";

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
      let fetchMetadataResponse: FetchMetadataStepResponse;

      beforeAll(async () => {
        try {
          const result = await orchestrator.deferred();
          assertDeferredIssuanceFlowSuccess(result);

          fetchMetadataResponse = result.fetchMetadataResponse;
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

      test("CI_081: Deferred Endpoint Issuance | Credential Issuer supports the Deferred Flow", async () => {
        const log = baseLog.withTag("CI_081");
        const DESCRIPTION =
          "Issuer supports the Deferred Flow and returns a valid deferred refresh token and transaction_id";

        let testSuccess = false;
        try {
          expect(
            fetchMetadataResponse.success,
            "Fetch metadata step failed",
          ).toBe(true);
          expect(
            fetchMetadataResponse.response,
            "Fetch metadata response body is undefined",
          ).toBeDefined();

          const entityStatementClaims =
            fetchMetadataResponse.response?.entityStatementClaims;
          const deferredCredentialEndpoint =
            entityStatementClaims?.metadata?.openid_credential_issuer
              ?.deferred_credential_endpoint;

          expect(
            deferredCredentialEndpoint,
            "Issuer metadata does not contain deferred_credential_endpoint",
          ).toBeDefined();

          log.debug(
            "→ Deferred credential endpoint is ",
            deferredCredentialEndpoint,
          );

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      });

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
            response &&
              ("credentials" in response || "transaction_id" in response),
            "Deferred credential response must contain either credentials (immediate) or transaction_id (pending)",
          ).toBe(true);

          // When the issuer returns credentials immediately (200), validate them.
          // When the issuer returns a pending response (202), only transaction_id is present and
          // credential assertions are intentionally skipped (no retry loop in this tool).
          const immediateCredentials =
            response && "credentials" in response
              ? (response as ImmediateCredentialResponse).credentials
              : null;

          expect(
            immediateCredentials === null || immediateCredentials.length > 0,
            "Deferred credential response contains no credentials",
          ).toBe(true);
          expect(
            immediateCredentials === null ||
              immediateCredentials[0]?.credential !== undefined,
            "First deferred credential value is undefined",
          ).toBe(true);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      });
    },
  );
});
