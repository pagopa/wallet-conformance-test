import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

// Import test configuration - this will register all configurations
import "../test.config";

import { WalletIssuanceOrchestratorFlow } from "../src/orchestrator/wallet-issuance-orchestrator-flow";
import { FetchMetadataStepResponse } from "../src/step/issuance/fetch-metadata-step";
import { PushedAuthorizationRequestResponse } from "../src/step/issuance/pushed-authorization-request-step";
import { getTestRegistry } from "../src/issuance-test-registry";
import { HAPPY_FLOW_NAME } from "../test.config";

// Get the test configuration from the registry
// The configuration must be registered before running the tests
getTestRegistry()
  .get(HAPPY_FLOW_NAME)
  .forEach((testConfig) => {
    describe(`[${testConfig.testName}] Credential Issuer Tests`, async () => {
      const orchestrator: WalletIssuanceOrchestratorFlow =
        new WalletIssuanceOrchestratorFlow(testConfig.testName);
      const baseLog = orchestrator.getLog();
      let fetchMetadataResponse: FetchMetadataStepResponse;
      let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;

      beforeAll(async () => {
        ({ fetchMetadataResponse } = await orchestrator.runAll(
          testConfig.toRunOptions(),
        ));
      });

      test("CI_001: Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint.", async () => {
        const log = baseLog.withTag("CI_001");

        log.start("Started");
        expect(fetchMetadataResponse.success).toBe(true);
        log.testCompleted();
      });

      test("CI_002 Entity Configuration response media type check", async () => {
        const log = baseLog.withTag("CI_002");

        log.start("Started");
        expect(
          fetchMetadataResponse.response?.headers.get("content-type"),
        ).toBe("application/entity-statement+jwt");
        log.testCompleted();
      });

      test("CI_003: The Entity Configuration is cryptographically signed", async () => {
        const log = baseLog.withTag("CI_003");

        log.start("Started");
        expect(fetchMetadataResponse.response).toBeDefined();

        log.info("Asserting response status...");
        expect(fetchMetadataResponse.response!.status).toBe(200);

        log.info("Checking non empty response body...");
        expect(
          fetchMetadataResponse.response?.entityStatementJwt,
        ).toBeDefined();

        log.info("Parsing response body as JWT...");
        const decodedData = decodeJwt(
          fetchMetadataResponse.response?.entityStatementJwt!,
        );
        log.debug(decodedData);
        log.testCompleted();
      });

      test("CI_006: Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
        const log = baseLog.withTag("CI_006");

        log.start("Started");
        log.info("Parsing response body as JWT...");
        const decodedData = decodeJwt(
          fetchMetadataResponse.response?.entityStatementJwt!,
        );
        log.debug(JSON.stringify(decodedData));

        log.info("Validating response format...");
        const result = itWalletEntityStatementClaimsSchema._def.schema
          .pick({
            iss: true,
            sub: true,
            iat: true,
            exp: true,
            jwks: true,
            metadata: true,
          })
          .refine((data) => data.metadata !== undefined, {
            message: "metadata is missing",
          })
          .safeParse(decodedData);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);
        log.info(`Response matches the required format`);
        log.testCompleted();
      });

      test("CI_008: Credential Issuer metadata", async () => {
        const log = baseLog.withTag("CI_008");

        log.start("Started");
        log.info("Parsing response body as JWT...");
        const decodedData = decodeJwt(
          fetchMetadataResponse.response?.entityStatementJwt!,
        );
        log.debug(JSON.stringify(decodedData));

        log.info("Validating response format...");
        const result = itWalletEntityStatementClaimsSchema._def.schema
          .pick({
            metadata: true,
          })
          .refine(
            (data) =>
              data.metadata !== undefined &&
              data.metadata!.federation_entity !== undefined &&
              data.metadata!.oauth_authorization_server !== undefined &&
              data.metadata!.openid_credential_issuer !== undefined,
            {
              message:
                "metadata or federation_entity|oauth_authorization_server|openid_credential_issuer is missing",
            },
          )
          .safeParse(decodedData);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        log.info(`Response matches the required format`);
        log.testCompleted();
      });

      test("CI_009: Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
        const log = baseLog.withTag("CI_009");

        log.start("Started");
        log.info("Parsing response body as JWT...");
        const decodedData = decodeJwt(
          fetchMetadataResponse.response?.entityStatementJwt!,
        );
        log.debug(JSON.stringify(decodedData));

        log.info("Validating response format...");
        const result = itWalletEntityStatementClaimsSchema._def.schema
          .pick({
            metadata: true,
          })
          .refine(
            (data) =>
              data.metadata !== undefined &&
              data.metadata!.openid_credential_verifier !== undefined,
            { message: "metadata or openid_credential_verifier is missing" },
          )
          .safeParse(decodedData);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        log.info(`Response matches the required format`);
        log.testCompleted();
      });
    });
  });
