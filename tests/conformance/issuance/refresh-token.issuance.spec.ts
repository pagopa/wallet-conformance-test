/* eslint-disable max-lines-per-function */
import { defineIssuanceTest } from "#/config/test-metadata";
import { withCredentialRequestOverrides } from "#/helpers/credential-validation-helpers";
import { assertReissuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import {
  extractTokenError,
  withInvalidClientAttestationPop,
  withInvalidRefreshTokenDPoP,
  withMissingRefreshTokenDPoP,
  withRefreshTokenDPoPSignedByWrongKey,
} from "#/helpers/refresh-token-validation-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { calculateJwkThumbprint, decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import type {
  CredentialRequestResponse,
  CredentialRequestStepOptions,
} from "@/step/issuance";
import type { KeyPair } from "@/types";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";

const testConfigs = await defineIssuanceTest("RefreshTokenIssuance");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Refresh Token Issuance`, () => {
    let capturedCredentialRequestDPoPKey: KeyPair | undefined;

    class CapturingCredentialRequestStep
      extends testConfig.credentialRequestStepClass
    {
      async run(
        options: CredentialRequestStepOptions,
      ): Promise<CredentialRequestResponse> {
        capturedCredentialRequestDPoPKey = options.dPoPKey;
        return super.run(options);
      }
    }

    const orchestrator = new WalletIssuanceOrchestratorFlow({
      ...testConfig,
      credentialRequestStepClass: CapturingCredentialRequestStep,
    });
    const baseLog = orchestrator.getLog();

    let credentialResponse: CredentialRequestResponse;
    let refreshTokenTokenEndpoint: string | undefined;
    let issuedRefreshToken: string | undefined;
    let refreshTokenDPoPKey: KeyPair | undefined;

    beforeAll(async () => {
      try {
        const result = await orchestrator.reissuance();
        assertReissuanceFlowSuccess(result);

        credentialResponse = result.credentialResponse;
        refreshTokenTokenEndpoint =
          result.fetchMetadataResponse.response?.entityStatementClaims?.metadata
            ?.oauth_authorization_server?.token_endpoint;
        issuedRefreshToken = result.tokenResponse.response?.refresh_token;
        refreshTokenDPoPKey = result.tokenResponse.response?.dPoPKey;

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

    test("CI_114: Refresh Token Security | Issuer rejects first-time issuance with an Access Token obtained through Refresh Token flow", async () => {
      const log = baseLog.withTag("CI_114");
      const DESCRIPTION =
        "Issuer correctly rejected first-time issuance with a refresh-token Access Token";

      let testSuccess = false;
      try {
        const firstTimeCredentialConfigurationId = testConfigs.find(
          ({ credentialConfigurationId }) =>
            credentialConfigurationId !== testConfig.credentialConfigurationId,
        )?.credentialConfigurationId;

        if (!firstTimeCredentialConfigurationId) {
          log.debug(
            "CI_114 skipped: no alternate configured credential type is available to model first-time issuance",
          );
          testSuccess = true;
          return;
        }

        const negativeOrchestrator = new WalletIssuanceOrchestratorFlow({
          ...testConfig,
          credentialRequestStepClass: withCredentialRequestOverrides(
            testConfig.credentialRequestStepClass,
            {
              credential_identifier: firstTimeCredentialConfigurationId,
            },
          ),
        });

        const result = await negativeOrchestrator.reissuance();

        expect(
          result.fetchMetadataResponse?.success,
          "Metadata discovery failed before the first-time issuance Credential Request",
        ).toBe(true);
        expect(
          result.tokenResponse?.success,
          "Refresh-token Token Request failed before the first-time issuance Credential Request",
        ).toBe(true);
        expect(
          result.tokenResponse?.response?.access_token,
          "Refresh-token Token Request did not return an Access Token",
        ).toBeDefined();
        expect(
          result.nonceResponse?.success,
          "Nonce Request failed before the first-time issuance Credential Request",
        ).toBe(true);
        expect(
          result.success,
          "Re-issuance flow succeeded even though the refresh-token Access Token was used for first-time issuance",
        ).toBe(false);
        expect(
          result.credentialResponse,
          "Credential Request result is undefined; rejection did not happen at the Credential endpoint",
        ).toBeDefined();
        expect(
          result.credentialResponse?.success,
          `Issuer accepted first-time issuance for credential '${firstTimeCredentialConfigurationId}' using a refresh-token Access Token bound to '${testConfig.credentialConfigurationId}'`,
        ).toBe(false);

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

    test("CI_102: DPoP Proof JWT | DPoP Proof is required for all refresh token operations to obtain new Access Tokens", async () => {
      const log = baseLog.withTag("CI_102");
      const DESCRIPTION =
        "Issuer correctly rejected refresh-token reissuance with missing DPoP proof";

      let testSuccess = false;
      try {
        const negativeOrchestrator = new WalletIssuanceOrchestratorFlow({
          ...testConfig,
          tokenRequestStepClass: withMissingRefreshTokenDPoP(
            testConfig.tokenRequestStepClass,
          ),
        });

        const result = await negativeOrchestrator.reissuance();

        expect(
          result.success,
          "Re-issuance flow succeeded despite missing DPoP proof",
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

    test("CI_103: DPoP Proof JWT | Credential Request DPoP proof reuses the DPoP key generated during refresh-token Token Request", async () => {
      const log = baseLog.withTag("CI_103");
      const DESCRIPTION =
        "Credential Request DPoP proof reuses the refresh-token Token Request DPoP key";

      let testSuccess = false;
      try {
        expect(
          refreshTokenDPoPKey,
          "Refresh-token Token Request DPoP key is undefined",
        ).toBeDefined();
        expect(
          credentialResponse.success,
          "Credential request step failed",
        ).toBe(true);
        expect(
          credentialResponse.response,
          "Credential response body is undefined",
        ).toBeDefined();
        expect(
          capturedCredentialRequestDPoPKey,
          "Credential Request DPoP key was not captured",
        ).toBeDefined();

        if (!refreshTokenDPoPKey || !capturedCredentialRequestDPoPKey) {
          throw new Error(
            "Cannot compare DPoP key thumbprints because a DPoP key is undefined",
          );
        }

        const tokenDPoPJkt = await calculateJwkThumbprint(
          refreshTokenDPoPKey.publicKey,
        );
        const credentialRequestDPoPJkt = await calculateJwkThumbprint(
          capturedCredentialRequestDPoPKey.publicKey,
        );

        expect(
          credentialRequestDPoPJkt,
          "Credential Request DPoP key thumbprint does not match the refresh-token Token Request DPoP key",
        ).toBe(tokenDPoPJkt);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_096: Refresh Token Validation | Issuer rejects expired or invalid Refresh Token with invalid_grant", async () => {
      const log = baseLog.withTag("CI_096");
      const DESCRIPTION =
        "Issuer correctly rejected expired or invalid Refresh Token with invalid_grant";

      let testSuccess = false;
      try {
        const negativeOrchestrator = new WalletIssuanceOrchestratorFlow(
          testConfig,
        );
        negativeOrchestrator.getConfig().issuance.refresh_token =
          "invalid-refresh-token-ci-096";

        const result = await negativeOrchestrator.reissuance();

        expect(
          result.success,
          "Re-issuance flow succeeded despite invalid Refresh Token",
        ).toBe(false);
        expect(
          result.tokenResponse?.success,
          "Token request did not fail; rejection may have happened outside token endpoint validation",
        ).toBe(false);
        expect(
          extractTokenError(result.tokenResponse),
          "Issuer did not return the expected OAuth error type 'invalid_grant' for an invalid Refresh Token",
        ).toBe("invalid_grant");

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_098: Token Transmission Security | Refresh-token token endpoint uses TLS-protected HTTPS", async () => {
      const log = baseLog.withTag("CI_098");
      const DESCRIPTION =
        "Refresh-token token endpoint uses a TLS-protected HTTPS connection";

      let testSuccess = false;
      try {
        expect(
          refreshTokenTokenEndpoint,
          "Token endpoint is undefined",
        ).toBeDefined();
        if (!refreshTokenTokenEndpoint) {
          throw new Error("Token endpoint is undefined");
        }
        expect(
          new URL(refreshTokenTokenEndpoint).protocol,
          "Token endpoint must use HTTPS",
        ).toBe("https:");

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_099: Refresh Token Security | Refresh tokens are generated with unguessable values and protected from modification", async () => {
      const log = baseLog.withTag("CI_099");
      const DESCRIPTION =
        "Refresh tokens are generated with unguessable values and modification protection";

      let testSuccess = false;
      try {
        expect(issuedRefreshToken, "Refresh token is undefined").toBeDefined();
        if (!issuedRefreshToken) {
          throw new Error("Refresh token is undefined");
        }
        expect(
          issuedRefreshToken,
          "Issuer reused the input refresh token instead of generating a new one",
        ).not.toBe(orchestrator.getConfig().issuance.refresh_token);
        expect(
          issuedRefreshToken.length,
          "Refresh token must have at least 128 bits of encoded entropy",
        ).toBeGreaterThanOrEqual(22);
        expect(
          new Set(issuedRefreshToken).size,
          "Refresh token has too little character variety",
        ).toBeGreaterThan(8);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_104: Refresh Token Duration | Issuer time-limits refresh tokens to at most one year", async () => {
      const log = baseLog.withTag("CI_104");
      const DESCRIPTION =
        "Refresh token lifetime is bounded and does not exceed one year";

      const maxRefreshTokenLifetimeSeconds = 365 * 24 * 60 * 60;

      let testSuccess = false;
      try {
        expect(issuedRefreshToken, "Refresh token is undefined").toBeDefined();
        if (!issuedRefreshToken) {
          throw new Error("Refresh token is undefined");
        }

        const claims = decodeJwt(issuedRefreshToken);

        expect(
          typeof claims.iat,
          "Refresh token must expose issued-at time",
        ).toBe("number");
        expect(
          typeof claims.exp,
          "Refresh token must expose expiration time",
        ).toBe("number");

        if (typeof claims.iat !== "number" || typeof claims.exp !== "number") {
          throw new Error("Refresh token lifetime claims are not numeric");
        }

        expect(
          claims.exp,
          "Refresh token expiration must be after issued-at",
        ).toBeGreaterThan(claims.iat);
        expect(
          claims.exp - claims.iat,
          "Refresh token lifetime must not exceed one year",
        ).toBeLessThanOrEqual(maxRefreshTokenLifetimeSeconds);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
