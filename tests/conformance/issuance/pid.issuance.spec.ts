/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import {
  assertPidJwtPayloadClaims,
  assertPidSdDisclosures,
} from "#/helpers/pid-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { SDJwt } from "@sd-jwt/core";
import { digest } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  getCredentialResponseCredentials,
} from "@/step/issuance";

const testConfigs = await defineIssuanceTest("HappyFlowIssuance");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] PID Credential Issuer Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let authorizeResponse: AuthorizeStepResponse;
    let credentialResponse: CredentialRequestResponse;
    const sdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
    });

    beforeAll(async () => {
      try {
        const result = await orchestrator.issuance();
        assertIssuanceFlowSuccess(result);

        authorizeResponse = result.authorizeResponse;
        credentialResponse = result.credentialResponse;

        baseLog.info("Issuance flow completed successfully");
      } catch (e) {
        baseLog.error(e);
        throw e;
      } finally {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    });

    useTestSummary(baseLog, testConfig.name);

    test(
      "CI_051: CieID High-Level Authentication | PID Provider successfully performs User authentication based on CieID scheme with LoAHigh (CIE L3)",
      { skip: testConfig.credentialConfigurationId !== "dc_sd_jwt_pid" },
      async () => {
        const log = baseLog.withTag("CI_051");
        const DESCRIPTION =
          "PID Provider successfully performs User authentication based on CieID scheme with LoAHigh (CIE L3)";

        log.start(
          "Conformance test: Verifying PID Provider performs User authentication based on CieID scheme with LoAHigh (CIE L3)",
        );

        let testSuccess = false;
        try {
          const credentials = getCredentialResponseCredentials(
            credentialResponse.response,
          );
          expect(credentials.length).toBeGreaterThan(0);
          log.debug(`  Credentials received: ${credentials.length}`);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

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

    test(
      "CI_117: Credential | The Italian PID is successfully provided with the User attributes defined in the PID table",
      { skip: testConfig.credentialConfigurationId !== "dc_sd_jwt_pid" },
      async () => {
        const log = baseLog.withTag("CI_117");
        const DESCRIPTION =
          "Italian PID contains all mandatory user attributes as SD disclosures and required metadata claims";

        log.start(
          "Conformance test: Verifying Italian PID user attributes and metadata claims",
        );

        let testSuccess = false;
        try {
          const isV1_0 = sdkConfig.isVersion(ItWalletSpecsVersion.V1_0);

          const sdJwtCredentials: string[] = [];
          for (const credObj of getCredentialResponseCredentials(
            credentialResponse.response,
          )) {
            try {
              await SDJwt.extractJwt(credObj.credential);
              sdJwtCredentials.push(credObj.credential);
            } catch {
              /* non-SD-JWT, skip */
            }
          }

          expect(
            sdJwtCredentials.length,
            "At least one SD-JWT PID credential must be present",
          ).toBeGreaterThan(0);

          const instance = new SDJwtVcInstance({ hasher: digest });

          for (const credentialJwt of sdJwtCredentials) {
            const decoded = await instance.decode(credentialJwt);
            const payload = decoded.jwt?.payload as Record<string, unknown>;

            const disclosureMap = new Map<string, unknown>();
            for (const disc of decoded.disclosures ?? []) {
              if (disc.key !== undefined)
                disclosureMap.set(disc.key, disc.value);
            }

            log.debug(
              `  Disclosed claims: ${JSON.stringify([...disclosureMap.keys()])}`,
            );

            assertPidSdDisclosures(disclosureMap, isV1_0);
            assertPidJwtPayloadClaims(payload, isV1_0);

            log.debug(
              "  ✓ All mandatory PID user attributes and metadata claims validated",
            );
          }

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test(
      "CI_136: Additional PID Claims | Additional claims data is successfully incorporated when required",
      { skip: testConfig.credentialConfigurationId !== "dc_sd_jwt_pid" },
      async () => {
        const log = baseLog.withTag("CI_136");
        const DESCRIPTION =
          "Italian PID contains all mandatory user attributes as SD disclosures and required metadata claims";

        log.start(
          "Conformance test: Verifying Italian PID user attributes and metadata claims",
        );

        let testSuccess = false;
        try {
          const isV1_0 = sdkConfig.isVersion(ItWalletSpecsVersion.V1_0);

          const sdJwtCredentials: string[] = [];
          for (const credObj of getCredentialResponseCredentials(
            credentialResponse.response,
          )) {
            try {
              await SDJwt.extractJwt(credObj.credential);
              sdJwtCredentials.push(credObj.credential);
            } catch {
              /* non-SD-JWT, skip */
            }
          }

          expect(
            sdJwtCredentials.length,
            "At least one SD-JWT PID credential must be present",
          ).toBeGreaterThan(0);

          const instance = new SDJwtVcInstance({ hasher: digest });

          for (const credentialJwt of sdJwtCredentials) {
            const decoded = await instance.decode(credentialJwt);
            const payload = decoded.jwt?.payload as Record<string, unknown>;

            const disclosureMap = new Map<string, unknown>();
            for (const disc of decoded.disclosures ?? []) {
              if (disc.key !== undefined)
                disclosureMap.set(disc.key, disc.value);
            }

            log.debug(
              `  Disclosed claims: ${JSON.stringify([...disclosureMap.keys()])}`,
            );

            assertPidSdDisclosures(disclosureMap, isV1_0);
            assertPidJwtPayloadClaims(payload, isV1_0);

            log.debug(
              "  ✓ All mandatory PID user attributes and metadata claims validated",
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
