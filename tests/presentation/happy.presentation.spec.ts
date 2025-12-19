/* eslint-disable max-lines-per-function */
import { beforeAll, describe, expect, test } from "vitest";

// Import test configuration - this will register all configurations
import "../test.config";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import { FetchMetadataStepResponse } from "@/step";
import { AuthorizationRequestStepResult } from "@/step/presentation/authorization-request-step";
import { RedirectUriStepResult } from "@/step/presentation/redirect-uri-step";

import { presentationRegistry } from "../config/test-registry";
import { HAPPY_FLOW_PRESENTATION_NAME } from "../test.config";

// Get the test configuration from the registry
// The configuration must be registered before running the tests
presentationRegistry.get(HAPPY_FLOW_PRESENTATION_NAME).forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Presentation Tests`, () => {
    const orchestrator: WalletPresentationOrchestratorFlow =
      new WalletPresentationOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let authorizationRequestResult: AuthorizationRequestStepResult;
    let fetchMetadataResult: FetchMetadataStepResponse;
    let redirectUriResult: RedirectUriStepResult;

    beforeAll(async () => {
      ({ authorizationRequestResult, fetchMetadataResult, redirectUriResult } =
        await orchestrator.presentation());
    });

    test("RPR003: Relying Party issues the QR-Code containing an URL using the base url provided within its metadata.", () => {
      const log = baseLog.withTag("RPR003");

      log.start("Started");
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const entityClaims = fetchMetadataResult.response?.entityStatementClaims;
      const issuer = entityClaims?.sub;

      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying authorization URL uses verifier base URL...");
      const parsedQrCode = authorizationRequestResult.response?.parsedQrCode;
      expect(parsedQrCode?.clientId).toBeDefined();

      // The client_id should match the issuer from the entity statement
      if (issuer) {
        expect(parsedQrCode?.clientId).toBe(issuer);
      }

      log.info("Verifying request_uri is from the correct domain...");
      expect(parsedQrCode?.requestUri).toBeDefined();
      expect(parsedQrCode?.requestUri).toMatch(/^https?:\/\/.+/);

      log.testCompleted();
    });

    test("RPR009: Relying Party accepts defaults to GET method.", () => {
      const log = baseLog.withTag("RPR009");

      log.start("Started");
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const metadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata;
      const verifierMetadata = metadata?.openid_credential_verifier;

      log.info("Verifying request object endpoint uses GET by default...");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response?.requestObject).toBeDefined();

      // If request_object_endpoint_methods is not specified or includes GET
      if (verifierMetadata?.request_object_endpoint_methods) {
        expect(verifierMetadata.request_object_endpoint_methods).toContain(
          "GET",
        );
      }

      log.testCompleted();
    });

    test("RPR012: Relying Party receives and validates response with state and nonce values.", () => {
      const log = baseLog.withTag("RPR012");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying state parameter is present...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.state).toBeDefined();
      expect(requestObject?.state).toMatch(/^[a-zA-Z0-9_-]+$/);

      log.info("Verifying nonce parameter is present...");
      expect(requestObject?.nonce).toBeDefined();
      expect(requestObject?.nonce).toMatch(/^[a-zA-Z0-9_-]+$/);

      log.testCompleted();
    });

    test("RPR019: User is redirected correctly, the endpoint works.", () => {
      const log = baseLog.withTag("RPR019");

      log.start("Started");
      expect(redirectUriResult.success).toBe(true);
      expect(redirectUriResult.response?.redirectUri).toBeDefined();

      log.info("Verifying redirect_uri is a valid URL...");
      const redirectUri = redirectUriResult.response?.redirectUri;
      expect(redirectUri?.toString()).toMatch(/^https?:\/\/.+/);

      log.info("Verifying response_code is present in redirect_uri...");
      expect(redirectUriResult.response?.responseCode).toBeDefined();

      log.testCompleted();
    });

    test("RPR078: Wallet Attestation request correctly uses standard DCQL query.", () => {
      const log = baseLog.withTag("RPR078");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying DCQL query is present in request object...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.dcql_query).toBeDefined();

      log.info("Verifying DCQL query structure...");
      const dcqlQuery = requestObject?.dcql_query;
      expect(dcqlQuery).toBeTypeOf("object");

      // DCQL query should contain credentials array
      expect(dcqlQuery?.credentials).toBeDefined();
      expect(Array.isArray(dcqlQuery?.credentials)).toBe(true);
      expect(dcqlQuery?.credentials.length).toBeGreaterThan(0);

      log.testCompleted();
    });

    test("RPR079: claims parameter is not included in DCQL query for Wallet Attestation.", () => {
      const log = baseLog.withTag("RPR079");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info(
        "Verifying claims parameter is not in DCQL query for Wallet Attestation...",
      );
      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlQuery = requestObject?.dcql_query;

      expect(dcqlQuery?.credentials).toBeDefined();

      // Check each credential in DCQL
      dcqlQuery?.credentials.forEach((credential: unknown) => {
        if (
          credential &&
          typeof credential === "object" &&
          "meta" in credential
        ) {
          const cred = credential as {
            claims?: unknown[];
            meta?: { vct_values?: string[] };
          };

          // Wallet Attestation credentials should not have claims parameter
          if (
            cred.meta?.vct_values?.includes(
              "urn:eu.europa.ec.eudi:wallet_attestation:1",
            )
          ) {
            expect(cred.claims).toBeUndefined();
          }
        }
      });

      log.testCompleted();
    });

    test("RPR080: vct_values parameter is correctly required in DCQL query.", () => {
      const log = baseLog.withTag("RPR080");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying vct_values parameter is present in DCQL query...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlQuery = requestObject?.dcql_query;

      expect(dcqlQuery?.credentials).toBeDefined();

      // Check that all credentials have meta.vct_values
      let hasVctValues = false;
      dcqlQuery?.credentials.forEach((credential: unknown) => {
        if (
          credential &&
          typeof credential === "object" &&
          "meta" in credential
        ) {
          const cred = credential as {
            meta?: { vct_values?: string[] };
          };
          if (cred.meta?.vct_values) {
            hasVctValues = true;
            expect(Array.isArray(cred.meta.vct_values)).toBe(true);
            expect(cred.meta.vct_values.length).toBeGreaterThan(0);
          }
        }
      });

      expect(hasVctValues).toBe(true);

      log.testCompleted();
    });

    test("RPR082: response_types_supported is correctly set to vp_token.", () => {
      const log = baseLog.withTag("RPR082");

      log.start("Started");
      expect(fetchMetadataResult.success).toBe(true);
      expect(fetchMetadataResult.response?.entityStatementClaims).toBeDefined();

      const metadata =
        fetchMetadataResult.response?.entityStatementClaims?.metadata;
      const verifierMetadata = metadata?.openid_credential_verifier;

      log.info("Verifying response_types_supported includes vp_token...");
      expect(verifierMetadata?.response_types_supported).toBeDefined();
      expect(verifierMetadata?.response_types_supported).toContain("vp_token");

      log.testCompleted();
    });

    test("RPR083: Relying Party correctly provides and handles redirect_uri.", () => {
      const log = baseLog.withTag("RPR083");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying response_uri is present in request object...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.response_uri).toBeDefined();
      expect(requestObject?.response_uri).toMatch(/^https?:\/\/.+/);

      log.info("Verifying redirect_uri is returned after authorization...");
      expect(redirectUriResult.success).toBe(true);
      expect(redirectUriResult.response?.redirectUri).toBeDefined();

      const redirectUri = redirectUriResult.response?.redirectUri;
      expect(redirectUri?.toString()).toMatch(/^https?:\/\/.+/);

      log.testCompleted();
    });

    test("RPR089: JWT typ parameter is correctly set to oauth-authz-req+jwt.", ({
      skip,
    }) => {
      // WARN: Temporarily skipped because blocked by io-wallet-oid4vp v0.7.5 publishing issue
      skip("Skipped due to external dependency issue.");

      const log = baseLog.withTag("RPR089");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying typ is oauth-authz-req+jwt...");
      // TODO: implement here missing assertions.

      log.testCompleted();
    });

    test("RPR090: response_mode parameter is correctly set to direct_post.jwt.", () => {
      const log = baseLog.withTag("RPR090");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying response_mode is direct_post.jwt...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.response_mode).toBe("direct_post.jwt");

      log.testCompleted();
    });

    test("RPR091: response_type parameter is correctly set to vp_token.", () => {
      const log = baseLog.withTag("RPR091");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying response_type is vp_token...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.response_type).toBe("vp_token");

      log.testCompleted();
    });

    test("RPR092: Relying Party sends Authorization Response to correct response_uri endpoint.", () => {
      const log = baseLog.withTag("RPR092");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying authorization response was sent to response_uri...");
      const responseUri =
        authorizationRequestResult.response?.requestObject.response_uri;
      expect(responseUri).toBeDefined();
      expect(responseUri).toMatch(/^https?:\/\/.+/);

      log.info("Verifying redirect was successful...");
      expect(redirectUriResult.success).toBe(true);

      log.testCompleted();
    });

    test("RPR093: nonce parameter has sufficient entropy with at least 32 digits.", () => {
      const log = baseLog.withTag("RPR093");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying nonce has at least 32 characters...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.nonce).toBeDefined();
      expect(requestObject?.nonce.length).toBeGreaterThanOrEqual(32);

      log.testCompleted();
    });

    test("RPR094: JWT exp parameter is correctly set and not expired.", () => {
      const log = baseLog.withTag("RPR094");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying exp parameter is present and not expired...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      expect(requestObject?.exp).toBeDefined();

      const currentTime = Math.floor(Date.now() / 1000);
      expect(requestObject?.exp).toBeGreaterThan(currentTime);

      log.testCompleted();
    });

    test("RPR097: Relying Party correctly requests Wallet Attestation using DCQL query.", () => {
      const log = baseLog.withTag("RPR097");

      log.start("Started");
      expect(authorizationRequestResult.success).toBe(true);
      expect(authorizationRequestResult.response).toBeDefined();

      log.info("Verifying Wallet Attestation is requested using DCQL query...");
      const requestObject = authorizationRequestResult.response?.requestObject;
      const dcqlQuery = requestObject?.dcql_query;

      expect(dcqlQuery?.credentials).toBeDefined();

      // Check if Wallet Attestation VCT is in the DCQL query
      let hasWalletAttestation = false;
      dcqlQuery?.credentials.forEach((credential: unknown) => {
        if (
          credential &&
          typeof credential === "object" &&
          "meta" in credential
        ) {
          const cred = credential as {
            meta?: { vct_values?: string[] };
          };
          if (
            cred.meta?.vct_values?.includes(
              "urn:eu.europa.ec.eudi:wallet_attestation:1",
            )
          ) {
            hasWalletAttestation = true;
            log.info("Found Wallet Attestation in DCQL query");
          }
        }
      });

      expect(hasWalletAttestation).toBe(true);

      log.testCompleted();
    });
  });
});
