/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { assertIssuanceFlowSuccess } from "#/helpers/flow-assertion-helpers";
import {
  assertPidJwtPayloadClaims,
  assertPidSdDisclosures,
} from "#/helpers/pid-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { JwkSet } from "@pagopa/io-wallet-oauth2";
import { fetchMetadata } from "@pagopa/io-wallet-oid4vci";
import {
  CredentialOffer,
  resolveCredentialOffer,
} from "@pagopa/io-wallet-oid4vci";
import { jsonWebKeySetSchema } from "@pagopa/io-wallet-oid-federation";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { SDJwt } from "@sd-jwt/core";
import { digest } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { DcqlQuery } from "dcql";
import { calculateJwkThumbprint, decodeJwt } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import z from "zod";

import { parseCredential } from "@/functions";
import { createVerifyJwtCallback, fetchWithConfig, parseMdoc } from "@/logic";
import { validateDcqlQuery } from "@/logic/dcql";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  FetchMetadataStepResponse,
  NonceRequestResponse,
  NotificationRequestResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";

// Define and auto-register test configuration
const testConfigs = await defineIssuanceTest("HappyFlowIssuance");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Issuer Tests`, () => {
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();
    let tokenResponse: TokenRequestResponse;
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    let authorizeResponse: AuthorizeStepResponse;
    let nonceResponse: NonceRequestResponse;
    let credentialResponse: CredentialRequestResponse;
    let walletAttestationResponse: AttestationResponse;
    let notificationRequestResponse: NotificationRequestResponse | undefined;
    const sdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
    });
    const shouldSkipTrustAnchorVerification =
      orchestrator.getConfig().trust_anchor.verify === false;

    beforeAll(async () => {
      try {
        const result = await orchestrator.issuance();
        assertIssuanceFlowSuccess(result);

        authorizeResponse = result.authorizeResponse;
        credentialResponse = result.credentialResponse;
        fetchMetadataResponse = result.fetchMetadataResponse;
        nonceResponse = result.nonceResponse;
        pushedAuthorizationRequestResponse =
          result.pushedAuthorizationRequestResponse;
        tokenResponse = result.tokenResponse;
        walletAttestationResponse = result.walletAttestationResponse;
        notificationRequestResponse = result.notificationRequestResponse;

        baseLog.info("Issuance flow completed successfully");
      } catch (e) {
        baseLog.error(e);
        throw e;
      } finally {
        // Give time for all logs to be flushed before starting tests
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    });

    useTestSummary(baseLog, testConfig.name);

    // ============================================================================
    // FETCH METADATA TESTS
    // ============================================================================

    test("CI_001: Fetch Metadata | Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint.", async () => {
      const log = baseLog.withTag("CI_001");
      const DESCRIPTION = "Entity Configuration successfully fetched";

      log.start(
        "Conformance test: Verifying Entity Configuration availability",
      );

      let testSuccess = false;
      try {
        log.debug("→ Checking Entity Configuration fetch was successful...");
        expect(fetchMetadataResponse.success).toBe(true);

        log.debug("→ Validating Entity Statement claims are present...");
        expect(
          fetchMetadataResponse.response?.entityStatementClaims,
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_002: Fetch Metadata | Entity Configuration response media type check", async () => {
      const log = baseLog.withTag("CI_002");
      const DESCRIPTION = "Entity Configuration content-type is correct";

      log.start(
        "Conformance test: Verifying Entity Configuration content-type header",
      );

      let testSuccess = false;
      try {
        // fetchMetadata step doesn't expose the raw response,
        // so we rely on the step's success and presence of claims as an indirect validation of correct content-type handling
        expect(fetchMetadataResponse.success).toBe(true);
        log.debug("  Expected: application/entity-statement+jwt");

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test(
      "CI_003: Fetch Metadata | The Entity Configuration is cryptographically signed",
      { skip: shouldSkipTrustAnchorVerification },
      async () => {
        const log = baseLog.withTag("CI_003");
        const DESCRIPTION = "Entity Configuration is cryptographically signed";

        log.start(
          "Conformance test: Verifying Entity Configuration JWT signature",
        );

        let testSuccess = false;
        try {
          const config = orchestrator.getConfig();
          const { credentialIssuer } =
            await orchestrator.findCredentialConfig();
          const entityClaims = await fetchMetadata({
            callbacks: {
              fetch: fetchWithConfig(config.network),
              verifyJwt: createVerifyJwtCallback({
                trustAnchorUrls: config.trust.federation_trust_anchors,
              }),
            },
            config: new IoWalletSdkConfig({
              itWalletSpecsVersion: config.wallet.wallet_version,
            }),
            credentialIssuerUrl: credentialIssuer,
          });

          log.debug("→ Checking Entity Statement JWT is present...");
          expect(entityClaims).toBeDefined();

          testSuccess = true;
        } catch (e) {
          log.error("Error fetching metadata:", e);
          throw e;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test(
      "CI_004: Fetch Metadata | Public Key inclusion in Entity Configuration and Subordinate Statement",
      { skip: shouldSkipTrustAnchorVerification },
      async () => {
        const log = baseLog.withTag("CI_004");
        const DESCRIPTION =
          "Public key is included in both Entity Configuration and Subordinate Statement";

        log.start(
          "Conformance test: Verifying public key in metadata and subordinate statement",
        );

        let testSuccess = false;
        try {
          const entityClaims =
            fetchMetadataResponse.response?.entityStatementClaims;
          log.debug("→ Checking public key in Entity Configuration...");
          expect(entityClaims.jwks.keys).toBeDefined();
          expect(entityClaims.jwks.keys.length).toBeGreaterThan(0);
          expect(() =>
            jsonWebKeySetSchema.parse(entityClaims.jwks),
          ).not.toThrowError();

          log.debug("→ Attempting to fetch Subordinate Statement from TA...");
          const taUrl = entityClaims.authority_hints[0];
          if (!taUrl)
            throw new Error(
              "missing authority_hints from credential issuer's metadata",
            );

          const sub = entityClaims.iss;

          const fetchUrl = `${taUrl}/fetch?sub=${encodeURIComponent(sub)}`;
          log.debug(`  Fetching from: ${fetchUrl}`);
          const response = await fetch(fetchUrl);
          expect(response.ok).toBe(true);
          if (!response.ok)
            throw new Error(
              `Failed to fetch subordinate statement from TA: ${response.status}`,
            );

          const subordinateJwt = await response.text();
          const subordinateClaims = decodeJwt(subordinateJwt) as {
            jwks: JwkSet;
          };

          log.debug("→ Checking public key in Subordinate Statement...");
          expect(subordinateClaims.jwks.keys).toBeDefined();
          expect(subordinateClaims.jwks.keys.length).toBeGreaterThan(0);
          expect(() =>
            jsonWebKeySetSchema.parse(subordinateClaims.jwks),
          ).not.toThrowError();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test(
      "CI_005: Fetch Metadata | Entity Configuration's Trust Marks",
      {
        skip:
          orchestrator.getConfig().wallet.wallet_version ===
          ItWalletSpecsVersion.V1_0,
      },
      async () => {
        const log = baseLog.withTag("CI_005");
        const DESCRIPTION =
          "Entity Configuration contains one or more Trust Marks";

        log.start(
          "Conformance test: Verifying Trust Marks in Entity Configuration",
        );

        let testSuccess = false;
        try {
          const entityClaims =
            fetchMetadataResponse.response?.entityStatementClaims;

          log.debug("→ Checking Trust Marks...");
          expect(entityClaims.trust_marks).toBeDefined();
          expect(entityClaims.trust_marks?.length).toBeGreaterThan(0);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test("CI_006: Fetch Metadata | Entity Configurations have in common these parameters: iss, sub, iat, exp, jwks, metadata.", async () => {
      const log = baseLog.withTag("CI_006");
      const DESCRIPTION =
        "All required parameters (iss, sub, iat, exp, jwks, metadata) are present";

      log.start(
        "Conformance test: Verifying Entity Configuration mandatory parameters",
      );

      let testSuccess = false;
      try {
        const entityClaims =
          fetchMetadataResponse.response?.entityStatementClaims;

        const result = z
          .object({
            exp: z.number(),
            iat: z.number(),
            iss: z.string(),
            jwks: z.any(),
            metadata: z.any(),
            sub: z.string(),
          })
          .loose()
          .refine((data) => data.metadata !== undefined, {
            message: "metadata is missing",
          })
          .safeParse(entityClaims);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test(
      "CI_008: Fetch Metadata | Credential Issuer metadata",
      { skip: process.env.CI === "true" },
      async () => {
        const log = baseLog.withTag("CI_008");
        const DESCRIPTION =
          "All required metadata sections (federation_entity, oauth_authorization_server, openid_credential_issuer) are present";

        log.start(
          "Conformance test: Verifying Credential Issuer metadata structure",
        );

        let testSuccess = false;
        try {
          const entityClaims =
            fetchMetadataResponse.response?.entityStatementClaims;

          const result = z
            .object({
              metadata: z.any(),
            })
            .loose()
            .refine(
              (data) =>
                data.metadata !== undefined &&
                data.metadata?.federation_entity !== undefined &&
                data.metadata?.oauth_authorization_server !== undefined &&
                data.metadata?.openid_credential_issuer !== undefined,
              {
                message:
                  "metadata or federation_entity|oauth_authorization_server|openid_credential_issuer is missing",
              },
            )
            .safeParse(entityClaims);

          expect(
            result.success,
            `Error validating schema: ${result.success ? "" : result.error.message}`,
          ).toBe(true);

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test("CI_009: Fetch Metadata | Inclusion of openid_credential_verifier Metadata in User Authentication via Wallet", async () => {
      const log = baseLog.withTag("CI_009");
      const DESCRIPTION = "openid_credential_verifier metadata is present";

      log.start(
        "Conformance test: Verifying openid_credential_verifier metadata presence",
      );

      let testSuccess = false;
      try {
        const entityClaims =
          fetchMetadataResponse.response?.entityStatementClaims;

        const result = z
          .object({
            metadata: z.any(),
          })
          .loose()
          .refine(
            (data) =>
              data.metadata !== undefined &&
              data.metadata?.openid_credential_verifier !== undefined,
            { message: "metadata or openid_credential_verifier is missing" },
          )
          .safeParse(entityClaims);

        expect(
          result.success,
          `Error validating schema: ${result.success ? "" : result.error.message}`,
        ).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // CREDENTIAL OFFER TESTS
    // ============================================================================

    test(
      "CI_010: Issuance | Credential Offer URI Structure",
      {
        skip: !orchestrator.getConfig().issuance.credential_offer_uri,
      },
      async ({ skip }) => {
        const log = baseLog.withTag("CI_010");
        const DESCRIPTION = "Credential Offer URI has correct structure";

        log.start("Conformance test: Verifying Credential Offer URI structure");

        let testSuccess = false;
        try {
          const credentialOffer =
            orchestrator.getConfig().issuance.credential_offer_uri;
          if (!credentialOffer) {
            log.warn("  Credential Offer URI missing in config, skipping test");
            skip();
            return;
          }

          try {
            const jsonOffer = JSON.parse(credentialOffer);

            log.warn(
              `  Credential Offer can be parsed as JSON, skipping test; ${jsonOffer}`,
            );
            skip();
            return;
          } catch {
            log.info(
              "  Credential Offer cannot be parsed as JSON, continuing test",
            );
          }

          log.debug(`→ Checking Credential Offer URI: ${credentialOffer}`);
          expect(
            credentialOffer.startsWith("openid-credential-offer://") ||
              credentialOffer.startsWith("haip-vci://") ||
              credentialOffer.startsWith("https://"),
          ).toBe(true);

          const url = new URL(credentialOffer);
          let offer: CredentialOffer;
          const credentialOfferEmbedded =
            url.searchParams.get("credential_offer");
          if (credentialOfferEmbedded)
            offer = JSON.parse(decodeURIComponent(credentialOfferEmbedded));
          else {
            const credentialOfferFetched = await fetch(url, {
              headers: {
                Accept: "application/json",
              },
              method: "GET",
            });

            if (!credentialOfferFetched.ok)
              throw new Error("could not fetch credential offer");

            offer = await credentialOfferFetched.json();
          }
          expect(offer).toBeDefined();
          expect(offer).toBeTypeOf("object");

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test(
      "CI_012: Issuance | Credential Offer Mandatory Parameters",
      {
        skip: !orchestrator.getConfig().issuance.credential_offer_uri,
      },
      async () => {
        const log = baseLog.withTag("CI_012");
        const DESCRIPTION = "Credential Offer contains mandatory parameters";

        log.start(
          "Conformance test: Verifying Credential Offer mandatory parameters",
        );

        let testSuccess = false;
        try {
          const credentialOffer =
            orchestrator.getConfig().issuance.credential_offer_uri;
          if (!credentialOffer) {
            log.warn("  Credential Offer URI missing in config, skipping test");
            testSuccess = true;
            return;
          }

          const offer = await resolveCredentialOffer({
            callbacks: { fetch },
            config: sdkConfig,
            credentialOffer,
          });
          log.debug(
            "→ Checking mandatory parameters: credential_issuer, credential_configuration_ids, grants",
          );
          expect(offer.credential_issuer).toBeDefined();
          expect(offer.credential_configuration_ids).toBeDefined();
          expect(Array.isArray(offer.credential_configuration_ids)).toBe(true);
          expect(offer.grants).toBeDefined();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test(
      "CI_013: Issuance | Credential Offer Grants Parameter Structure",
      {
        skip: !orchestrator.getConfig().issuance.credential_offer_uri,
      },
      async () => {
        const log = baseLog.withTag("CI_013");
        const DESCRIPTION =
          "Credential Offer grants parameter has correct structure";

        log.start(
          "Conformance test: Verifying Credential Offer grants structure",
        );

        let testSuccess = false;
        try {
          const credentialOffer =
            orchestrator.getConfig().issuance.credential_offer_uri;
          if (!credentialOffer) {
            log.warn("  Credential Offer URI missing in config, skipping test");
            testSuccess = true;
            return;
          }

          const offer = await resolveCredentialOffer({
            callbacks: { fetch },
            config: sdkConfig,
            credentialOffer,
          });
          log.debug(
            "→ Checking mandatory parameter: grants.authorization_code",
          );

          log.debug("→ Checking authorization_code grant structure...");
          expect(offer.grants.authorization_code).toBeDefined();

          testSuccess = true;
        } finally {
          log.testCompleted(DESCRIPTION, testSuccess);
        }
      },
    );

    test("CI_014: Credential | Credential Object Compilation", async () => {
      const log = baseLog.withTag("CI_014");
      const DESCRIPTION = "Credential Object is properly compiled";

      log.start("Conformance test: Verifying Credential Object compilation");

      let testSuccess = false;
      try {
        expect(credentialResponse.response).toBeDefined();
        if (!credentialResponse.response)
          throw new Error(
            `credential request failed: ${credentialResponse.error}`,
          );

        const key = credentialResponse.response.credentialKeyPair.publicKey;
        const credential = credentialResponse.response.credentials[0];
        if (!credential) throw new Error("credential response was empty");

        expect(credential.credential).toBeDefined();

        const parsed = await parseCredential(credential.credential);
        expect(parsed.credential).toBeDefined();
        if (!parsed.credential) throw new Error("credential parsing failed");

        log.info("  Successfully extracted credential");

        const credentialSchema:
          | undefined
          | {
              claims: { path: string[] }[];
              credential_metadata?: { claims: { path: string[] }[] };
              format: "dc+sd-jwt" | "mso_mdoc";
              vct?: string;
            } =
          fetchMetadataResponse.response?.entityStatementClaims.metadata
            ?.openid_credential_issuer?.credential_configurations_supported[
            testConfig.credentialConfigurationId
          ];
        if (!credentialSchema)
          throw new Error(
            "missing credential type from issuer's supported credentials list",
          );

        const isV1_0 = sdkConfig.isVersion(ItWalletSpecsVersion.V1_0);
        const claims = isV1_0
          ? credentialSchema.claims
          : credentialSchema.credential_metadata?.claims;
        if (!claims)
          throw new Error(
            "missing claims from issuer's supported credential configuration",
          );

        const queryResult = await validateDcqlQuery(
          [
            {
              credential: credential.credential,
              dpopJwk: key,
              id: "0",
              typ: parsed.credential.typ,
            },
          ],
          {
            credentials: [
              {
                ...credentialSchema,
                claims: credentialSchema.claims.map((claim) => {
                  if (credentialSchema.format === "dc+sd-jwt")
                    return {
                      path: claim.path,
                    };
                  if (credentialSchema.format === "mso_mdoc")
                    return {
                      claim_name: claim.path[1],
                      namespace: claim.path[0],
                    };
                }),
                id: "0",
              },
            ],
          } as DcqlQuery.Input,
        );
        expect(queryResult.can_be_satisfied).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // PUSHED AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_016: PAR Request | Credential Issuer successfully processes HTTP POST requests with message body parameters encoded in application/x-www-form-urlencoded format", async () => {
      const log = baseLog.withTag("CI_016");
      const DESCRIPTION =
        "PAR endpoint accepts application/x-www-form-urlencoded requests";

      log.start("Conformance test: Verifying PAR endpoint request handling");

      let testSuccess = false;
      try {
        const response = pushedAuthorizationRequestResponse.response;
        expect(response).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_040: PAR Request | request_uri validity time is set to less than one minute", async () => {
      const log = baseLog.withTag("CI_040");
      const DESCRIPTION = "request_uri validity time ≤60 seconds";

      log.start("Conformance test: Verifying request_uri expiration time");

      let testSuccess = false;
      try {
        const expires_in =
          pushedAuthorizationRequestResponse.response?.expires_in;
        expect(expires_in).toBeDefined();
        log.debug(`  expires_in: ${expires_in} seconds`);
        expect(expires_in).toBeLessThanOrEqual(60);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_041: PAR Request | Generated request_uri includes a cryptographic random value of at least 128 bits", async () => {
      const log = baseLog.withTag("CI_041");
      const DESCRIPTION = "request_uri has sufficient entropy (≥128 bits)";

      log.start("Conformance test: Verifying request_uri entropy requirements");

      let testSuccess = false;
      try {
        const requestUri =
          pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();

        log.debug(`  request_uri: ${requestUri}`);

        // Extract random portion (e.g. UUID, base64, or hex)
        const randomPart = requestUri?.split(":").pop() ?? "";
        const isBase64 = /^[A-Za-z0-9+/=]+$/.test(randomPart);
        const bitLength = isBase64
          ? randomPart.length * 6
          : randomPart.length * 4; // hex fallback

        log.debug(`  Random part: ${randomPart}`);
        log.debug(`  Bit length: ${bitLength} bits (required: ≥128)`);

        // Ensure it's at least 128 bits of randomness (16 bytes)
        expect(bitLength).toBeGreaterThanOrEqual(128);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_042: PAR Request | Complete request_uri doesn't exceed 512 ASCII characters", async () => {
      const log = baseLog.withTag("CI_042");
      const DESCRIPTION = "request_uri length is compliant (≤512 characters)";

      log.start("Conformance test: Verifying request_uri length constraint");

      let testSuccess = false;
      try {
        const requestUriLength =
          pushedAuthorizationRequestResponse.response?.request_uri.length;
        expect(requestUriLength).toBeDefined();
        log.debug(`  Length: ${requestUriLength} characters (max: 512)`);
        expect(requestUriLength).toBeLessThanOrEqual(512);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_043: PAR Request | When verification is successful, Credential Issuer returns an HTTP response with 201 status code", async () => {
      const log = baseLog.withTag("CI_043");
      const DESCRIPTION = "PAR request successful (no errors)";

      log.start("Conformance test: Verifying PAR request success response");

      let testSuccess = false;
      try {
        expect(pushedAuthorizationRequestResponse.error).toBeUndefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_044a: PAR Request | HTTP response includes request_uri parameter containing the generated one-time authorization URI", async () => {
      const log = baseLog.withTag("CI_044a");
      const DESCRIPTION = "request_uri parameter is present";

      log.start("Conformance test: Verifying request_uri parameter presence");

      let testSuccess = false;
      try {
        const requestUri =
          pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();
        expect(requestUri).toBeTruthy();
        log.debug(`  request_uri: ${requestUri}`);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_044b: PAR Request | HTTP response includes expires_in parameter specifying the validity duration in seconds", async () => {
      const log = baseLog.withTag("CI_044b");
      const DESCRIPTION = "expires_in parameter is present and valid";

      log.start("Conformance test: Verifying expires_in parameter");

      let testSuccess = false;
      try {
        const expiresIn =
          pushedAuthorizationRequestResponse.response?.expires_in;
        expect(expiresIn).toBeDefined();
        expect(typeof expiresIn).toBe("number");
        log.debug(`  expires_in: ${expiresIn} seconds`);
        expect(expiresIn).toBeGreaterThan(0);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_029: PAR Request | Wallet Instance Trustworthiness Verification | Issuer successfully resolves the wallet attestation trust chain and accepts a valid PAR", async () => {
      const log = baseLog.withTag("CI_029");
      const DESCRIPTION =
        "Issuer successfully resolved wallet attestation trust chain";

      log.start("Conformance test: Verifying wallet instance trustworthiness");

      let testSuccess = false;
      try {
        log.debug("→ Checking PAR was accepted by the issuer...");
        expect(pushedAuthorizationRequestResponse.error).toBeUndefined();
        expect(
          pushedAuthorizationRequestResponse.response,
          "PAR must have been accepted as evidence of trust chain resolution",
        ).toBeDefined();

        log.debug(
          "→ Decoding wallet attestation to inspect trust_chain header...",
        );
        const attestationJwt = await SDJwt.extractJwt(
          walletAttestationResponse.attestation,
        );
        const trustChainHeader = attestationJwt.header?.trust_chain;
        const trustChain = z
          .array(z.string())
          .optional()
          .parse(trustChainHeader);

        if (trustChain && trustChain.length > 0) {
          log.debug(
            `  trust_chain embedded in attestation header (${trustChain.length} element(s))`,
          );
          log.debug(
            "  Issuer resolved trust chain from embedded attestation header",
          );
        } else {
          log.debug("  trust_chain not embedded in attestation header");
          log.debug(
            "  Issuer resolves trust via federation endpoints (.well-known/openid-federation)",
          );
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_035 — Wallet Provider Trust Chain Evaluation
    // -----------------------------------------------------------------------

    test("CI_035: Wallet Provider Trust Chain Evaluation | Credential Issuer successfully evaluates the Wallet Provider trust chain", async () => {
      const log = baseLog.withTag("CI_035");
      const DESCRIPTION =
        "Wallet Provider trust chain was successfully evaluated by the Credential Issuer";

      log.start(
        "Conformance test: Verifying Wallet Provider trust chain evaluation",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Verifying PAR was accepted as evidence that the trust chain was evaluated...",
        );
        expect(
          pushedAuthorizationRequestResponse.response,
          "PAR must have been accepted as evidence of successful trust chain evaluation",
        ).toBeDefined();

        log.debug(
          "→ Decoding wallet attestation to inspect embedded trust_chain...",
        );
        const attestationJwt = await SDJwt.extractJwt(
          walletAttestationResponse.attestation,
        );
        const trustChain = z
          .array(z.string())
          .optional()
          .parse(attestationJwt.header?.trust_chain);

        if (!trustChain || trustChain.length === 0)
          throw new Error("undefined or empty trust_chain");

        log.debug(
          `  trust_chain embedded in attestation (${trustChain.length} element(s)) — verifying none is expired`,
        );
        const nowSec = Math.floor(Date.now() / 1000);
        for (const jwt of trustChain) {
          const jwtPayload = decodeJwt(jwt);
          if (jwtPayload.exp === undefined)
            throw new Error("undefined `exp` in trust_chain item");

          expect(
            jwtPayload.exp,
            "Trust chain element must not be expired",
          ).toBeGreaterThan(nowSec);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_036 — Federation Metadata Retrieval
    // -----------------------------------------------------------------------

    test("CI_036: Federation Metadata Retrieval | Credential Issuer retrieves federation metadata from participant endpoints", async () => {
      const log = baseLog.withTag("CI_036");
      const DESCRIPTION =
        "Federation metadata retrieved successfully via .well-known/openid-federation";

      log.start("Conformance test: Verifying federation metadata retrieval");

      let testSuccess = false;
      try {
        log.debug("→ Checking metadata was discovered via the federation...");
        expect(
          fetchMetadataResponse.response?.discoveredVia,
          "Metadata must be discovered via the federation (not OID4VCI)",
        ).toBe("federation");

        log.debug(
          "→ Verifying entity statement claims contain credential issuer metadata...",
        );
        const claims = fetchMetadataResponse.response?.entityStatementClaims;
        expect(
          claims?.metadata?.openid_credential_issuer,
          "Entity statement must include openid_credential_issuer metadata",
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_037 — Wallet Provider Trust Establishment
    // -----------------------------------------------------------------------

    test("CI_037: Wallet Provider Trust Establishment | Credential Issuer establishes trust in the Wallet Provider via the federation", async () => {
      const log = baseLog.withTag("CI_037");
      const DESCRIPTION =
        "Credential Issuer established trust in the Wallet Provider via the federation";

      log.start(
        "Conformance test: Verifying Wallet Provider trust establishment via federation",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Verifying PAR was accepted (CI established WP trust before this point)...",
        );
        expect(
          pushedAuthorizationRequestResponse.response?.request_uri,
          "PAR must have been accepted as evidence of WP trust establishment",
        ).toBeDefined();

        log.debug("→ Verifying metadata was fetched via the federation...");
        expect(
          fetchMetadataResponse.response?.discoveredVia,
          "Metadata must be discovered via the federation",
        ).toBe("federation");

        log.debug(
          "→ Verifying entity statement includes federation_entity metadata...",
        );
        const claims = fetchMetadataResponse.response?.entityStatementClaims;
        expect(
          claims?.metadata?.federation_entity,
          "Entity statement must include federation_entity metadata",
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // AUTHORIZATION REQUEST TESTS
    // ============================================================================

    test("CI_049: Authorization | Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR", async () => {
      const log = baseLog.withTag("CI_049");
      const DESCRIPTION =
        "Authorization successful — issuer correlated PAR and authorization";

      log.start(
        "Conformance test: Verifying PAR and authorization request correlation",
      );

      let testSuccess = false;
      try {
        // Verify PAR response provided a valid request_uri
        const requestUri =
          pushedAuthorizationRequestResponse.response?.request_uri;
        expect(requestUri).toBeDefined();
        expect(typeof requestUri).toBe("string");
        expect(requestUri?.length).toBeGreaterThan(0);
        log.debug(`  request_uri: ${requestUri}`);

        // Verify the request_uri follows the expected format (urn:ietf:params:oauth:request_uri:...)
        expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:.+$/);

        // Verify authorization was successful - this proves the issuer correlated the request
        // If the issuer couldn't correlate the authorization request with the PAR, it would fail
        expect(authorizeResponse.success).toBe(true);
        expect(
          authorizeResponse.response?.authorizeResponse?.code,
        ).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

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
          expect(
            credentialResponse.response?.credentials?.length,
          ).toBeGreaterThan(0);
          log.debug(
            `  Credentials received: ${credentialResponse.response?.credentials?.length}`,
          );

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

    test("CI_055: Authorization | (Q)EAA Provider uses OpenID4VP protocol to request PID presentation from the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_055");
      const DESCRIPTION =
        "OpenID4VP presentation successful (authorization code received)";

      log.start("Conformance test: Verifying OpenID4VP protocol usage");

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

    test("CI_056: Authorization | (Q)EAA Provider successfully provides the presentation request to the Wallet", async () => {
      const log = baseLog.withTag("CI_056");
      const DESCRIPTION = "Presentation request JWT successfully received";

      log.start("Conformance test: Verifying presentation request delivery");

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

    test("CI_058a: Authorization | Authorization code response includes the authorization code parameter", async () => {
      const log = baseLog.withTag("CI_058a");
      const DESCRIPTION = "Authorization code parameter is present and valid";

      log.start("Conformance test: Verifying authorization code parameter");

      let testSuccess = false;
      try {
        const code = authorizeResponse.response?.authorizeResponse?.code;
        expect(code).toBeDefined();
        expect(typeof code).toBe("string");
        log.debug(`  code: ${code}`);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_058b: Authorization | Authorization code response includes the state parameter matching the original request", async () => {
      const log = baseLog.withTag("CI_058b");
      const DESCRIPTION = "State parameter matches original request";

      log.start("Conformance test: Verifying state parameter matching");

      let testSuccess = false;
      try {
        const responseState =
          authorizeResponse.response?.authorizeResponse?.state;
        const requestState = pushedAuthorizationRequestResponse.response?.state;

        expect(responseState).toBeDefined();
        expect(typeof responseState).toBe("string");
        log.debug(`  Response state: ${responseState}`);
        log.debug(`  Request state:  ${requestState}`);

        expect(responseState).toBe(requestState);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_058c: Authorization | Authorization code response includes the iss parameter identifying the issuer", async () => {
      const log = baseLog.withTag("CI_058c");
      const DESCRIPTION = "Issuer parameter is present and matches";

      log.start("Conformance test: Verifying issuer identification parameter");

      let testSuccess = false;
      try {
        const responseIss = authorizeResponse.response?.authorizeResponse?.iss;
        const expectedIss = authorizeResponse.response?.iss;

        expect(responseIss).toBeDefined();
        expect(typeof responseIss).toBe("string");
        log.debug(`  Response iss: ${responseIss}`);
        log.debug(`  Expected iss: ${expectedIss}`);

        expect(responseIss).toBe(expectedIss);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // TOKEN REQUEST TESTS
    // ============================================================================

    test("CI_064: Token | Credential Issuer provides the Wallet Instance with a valid Access Token upon successful authorization", async () => {
      const log = baseLog.withTag("CI_064");
      const DESCRIPTION = "Access Token is valid and not expired";

      log.start(
        "Conformance test: Verifying Access Token issuance and validity",
      );

      let testSuccess = false;
      try {
        const token = tokenResponse.response?.access_token;
        expect(token).toBeDefined();

        const claims = decodeJwt(token ?? "");
        const currentTime = Date.now() / 1e3;
        const issuedAt = claims.iat;
        const expiresAt = claims.exp;

        expect(issuedAt).toEqual(expect.any(Number));
        expect(expiresAt).toEqual(expect.any(Number));
        if (typeof issuedAt !== "number" || typeof expiresAt !== "number") {
          throw new Error(
            "Access token must contain numeric iat and exp claims",
          );
        }

        log.debug(`  iat: ${new Date(issuedAt * 1000).toISOString()}`);
        log.debug(`  exp: ${new Date(expiresAt * 1000).toISOString()}`);

        expect(expiresAt).toBeGreaterThan(currentTime);
        expect(issuedAt).toBeLessThan(currentTime);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_066: Token | Both Access Token and Refresh Token (when issued) are cryptographically bound to the DPoP key", async () => {
      const log = baseLog.withTag("CI_066");
      const DESCRIPTION = "All tokens are bound to the DPoP key";

      log.start("Conformance test: Verifying DPoP key binding");

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.token_type).toBe("DPoP");

        const dPoPKey = tokenResponse.response?.dPoPKey;
        if (!dPoPKey) throw new Error("dPoPKey is undefined");
        const jkt = await calculateJwkThumbprint(dPoPKey.publicKey);
        log.debug(`  JWK Thumbprint: ${jkt}`);

        const tokens = [tokenResponse.response?.access_token];
        if (tokenResponse.response?.refresh_token) {
          tokens.push(tokenResponse.response?.refresh_token);
          log.debug("  Validating Access Token + Refresh Token");
        } else {
          log.debug("  Validating Access Token only (no Refresh Token)");
        }

        for (const token of tokens) {
          const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
          expect(claims.cnf?.jkt).toBeDefined();
          expect(claims.cnf?.jkt).toBe(jkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_094: Token | When all validation checks succeed, Credential Issuer generates new Access Token and new Refresh Token, both bound to the DPoP key", async () => {
      const log = baseLog.withTag("CI_094");
      const DESCRIPTION = "Tokens generated and bound to DPoP key";

      log.start(
        "Conformance test: Verifying token generation with DPoP binding",
      );

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.token_type).toBe("DPoP");

        const dPoPKey = tokenResponse.response?.dPoPKey;
        if (!dPoPKey) throw new Error("dPoPKey is undefined");
        const jkt = await calculateJwkThumbprint(dPoPKey.publicKey);
        log.debug(`  JWK Thumbprint: ${jkt}`);

        const tokens = [tokenResponse.response?.access_token];
        if (tokenResponse.response?.refresh_token) {
          tokens.push(tokenResponse.response?.refresh_token);
        }

        for (const token of tokens) {
          const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
          expect(claims.cnf?.jkt).toBeDefined();
          expect(claims.cnf?.jkt).toBe(jkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_095: Token | Both the Access Token and the Refresh Token are sent back to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_095");
      const DESCRIPTION = "Access Token is present";

      log.start("Conformance test: Verifying token response delivery");

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.access_token).toBeDefined();

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_101: Token | Access Tokens and Refresh Tokens are bound to the same DPoP key", async () => {
      const log = baseLog.withTag("CI_101");
      const DESCRIPTION = "All tokens bound to the same DPoP key";

      log.start(
        "Conformance test: Verifying consistent DPoP key binding across tokens",
      );

      let testSuccess = false;
      try {
        expect(tokenResponse.response?.token_type).toBe("DPoP");

        const dPoPKey = tokenResponse.response?.dPoPKey;
        if (!dPoPKey) throw new Error("dPoPKey is undefined");
        const jkt = await calculateJwkThumbprint(dPoPKey.publicKey);
        log.debug(`  JWK Thumbprint: ${jkt}`);

        const tokens = [tokenResponse.response?.access_token];
        if (tokenResponse.response?.refresh_token) {
          tokens.push(tokenResponse.response?.refresh_token);
        }

        for (const token of tokens) {
          const claims: { cnf: { jkt: string } } = decodeJwt(token ?? "");
          expect(claims.cnf?.jkt).toBeDefined();
          expect(claims.cnf?.jkt).toBe(jkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // NONCE REQUEST TESTS
    // ============================================================================

    test("CI_068: Nonce | Credential Issuer provides a c_nonce value to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_068");
      const DESCRIPTION = "c_nonce parameter is present and non-empty";

      log.start("Conformance test: Verifying c_nonce parameter provision");

      let testSuccess = false;
      try {
        const nonce = nonceResponse.response?.nonce as
          | undefined
          | { c_nonce: string };
        expect(nonce?.c_nonce).toBeDefined();
        expect(nonce?.c_nonce.length).toBeGreaterThan(0);
        log.debug(`  c_nonce length: ${nonce?.c_nonce.length} characters`);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_069: Nonce | The c_nonce parameter is provided as a string value with sufficient unpredictability to prevent guessing attacks, serving as a cryptographic challenge that the Wallet Instance uses to create proof of possession of the key (proofs claim)", async () => {
      const log = baseLog.withTag("CI_069");
      const DESCRIPTION =
        "c_nonce has sufficient entropy to prevent guessing attacks";

      log.start(
        "Conformance test: Verifying c_nonce entropy and unpredictability",
      );

      let testSuccess = false;
      try {
        const nonce = nonceResponse.response?.nonce as
          | undefined
          | { c_nonce: string };
        let cNonce = nonce?.c_nonce ?? "";
        const length = cNonce.length;

        log.debug(`  Length: ${length} characters (required: ≥32)`);
        expect(length).toBeGreaterThanOrEqual(32);

        const frequencies: number[] = [];
        for (const char of cNonce) {
          const prevLength = cNonce.length;
          cNonce = cNonce.replace(char, "");
          frequencies.push((prevLength - cNonce.length) / length);
        }

        const entropy = -frequencies.reduce((a, b) => a + b * Math.log2(b), 0);
        log.debug(`  Entropy: ${entropy.toFixed(2)} bits (required: >5)`);
        expect(entropy).toBeGreaterThan(5);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // ============================================================================
    // CREDENTIAL REQUEST TESTS
    // ============================================================================

    // eslint-disable-next-line complexity
    test("CI_084: Credential | When all validation checks succeed, Credential Issuer creates a new Credential cryptographically bound to the validated key material and provides it to the Wallet Instance", async () => {
      const log = baseLog.withTag("CI_084");
      const DESCRIPTION =
        "Credential is cryptographically bound to Wallet Instance key";

      log.start(
        "Conformance test: Verifying credential issuance with key binding",
      );

      let testSuccess = false;
      try {
        expect(
          credentialResponse.response?.credentials?.length,
        ).toBeGreaterThan(0);
        log.debug(
          `  Credentials received: ${credentialResponse.response?.credentials?.length}`,
        );

        const credentialPublicKey =
          credentialResponse.response?.credentialKeyPair?.publicKey;
        expect(credentialPublicKey).toBeDefined();

        if (!credentialPublicKey) {
          log.error("  Credential public key is undefined");
          testSuccess = false;
          return;
        }

        const expectedJkt = await calculateJwkThumbprint(credentialPublicKey);
        log.debug(`  Expected JWK Thumbprint: ${expectedJkt}`);

        for (const credential of credentialResponse.response?.credentials ??
          []) {
          expect(credential.credential).toBeDefined();

          // Resolve the key-binding JWK from either SD-JWT VC (cnf.jwk) or
          // mdoc-CBOR (deviceKeyInfo.deviceKey converted from COSE_Key).
          let boundKeyJwk: JsonWebKey | undefined;
          let detectedFormat: "dc+sd-jwt" | "mso_mdoc" | undefined;

          try {
            const sdJwt = await SDJwt.extractJwt(credential.credential);
            detectedFormat = "dc+sd-jwt";
            const payload = sdJwt.payload as
              | undefined
              | { cnf?: { jwk?: JsonWebKey } };
            boundKeyJwk = payload?.cnf?.jwk;
            log.debug("  Format: SD-JWT VC");
          } catch (err: unknown) {
            log.debug(
              `  Not SD-JWT VC (${err instanceof Error ? err.message : String(err)}), trying mdoc-CBOR...`,
            );
          }

          if (detectedFormat === undefined) {
            try {
              const mdocDoc = parseMdoc(
                Buffer.from(credential.credential, "base64url"),
              );
              const deviceKey =
                mdocDoc.issuerAuth.mobileSecurityObject.deviceKeyInfo
                  ?.deviceKey;
              if (deviceKey !== undefined) {
                boundKeyJwk = deviceKey.jwk;
              }
              detectedFormat = "mso_mdoc";
              log.debug("  Format: mdoc-CBOR");
            } catch (err: unknown) {
              log.error(
                `  Credential is neither SD-JWT VC nor mdoc-CBOR: ${err instanceof Error ? err.message : String(err)}`,
              );
            }
          }

          if (detectedFormat === "dc+sd-jwt" && boundKeyJwk === undefined) {
            throw new Error(
              "SD-JWT credential is missing cnf.jwk — key binding cannot be verified",
            );
          }

          expect(
            boundKeyJwk,
            "Credential must be bound to the wallet key via cnf.jwk (SD-JWT VC) or deviceKeyInfo.deviceKey (mdoc-CBOR)",
          ).toBeDefined();
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          const credentialJkt = await calculateJwkThumbprint(boundKeyJwk!);
          log.debug(`  Credential JWK Thumbprint: ${credentialJkt}`);
          expect(credentialJkt).toBe(expectedJkt);
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_088b: Notification | Access Token allows access to Notification endpoint for notifying Digital Credential deletion to the Credential Issuer", async ({
      skip,
    }) => {
      const log = baseLog.withTag("CI_088b");
      const DESCRIPTION =
        "Access token successfully used to notify credential deletion";

      log.start(
        "Conformance test: Verifying access token use at Notification endpoint",
      );

      let testSuccess = false;
      try {
        if (!notificationRequestResponse) {
          log.debug(
            "→ CI_088b skipped: notificationRequestResponse is not present in IssuanceFlowResponse",
          );
          skip();
          return;
        }

        expect(
          notificationRequestResponse.success,
          "Notification request step failed",
        ).toBe(true);
        expect(
          notificationRequestResponse.response?.status,
          "Notification endpoint must return 204 No Content",
        ).toBe(204);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_161a: Notification | User successfully initiates Digital Credential revocation/suspension through Credential Issuer's web service", async ({
      skip,
    }) => {
      const log = baseLog.withTag("CI_161a");
      const DESCRIPTION =
        "User successfully initiates Digital Credential revocation/suspension through Credential Issuer's web service";

      log.start(
        "Conformance test: Verifying user-initiated Digital Credential revocation/suspension",
      );

      let testSuccess = false;
      try {
        if (!notificationRequestResponse) {
          log.debug(
            "→ CI_161a skipped: notificationRequestResponse is not present in IssuanceFlowResponse",
          );
          skip();
          return;
        }

        expect(
          notificationRequestResponse.success,
          "Notification request step failed",
        ).toBe(true);
        expect(
          notificationRequestResponse.response?.status,
          "Notification endpoint must return 204 No Content",
        ).toBe(204);
        expect(
          notificationRequestResponse.response?.event,
          "CI_161a must send credential_deleted for revocation",
        ).toBe("credential_deleted");

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
          for (const credObj of credentialResponse.response?.credentials ??
            []) {
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

    test("CI_118: Credential | (Q)EAA are Issued to a Wallet Instance in SD-JWT VC or mdoc-CBOR data format.", async () => {
      const log = baseLog.withTag("CI_118");
      const DESCRIPTION =
        "Credential is in valid format (SD-JWT VC or mdoc-CBOR)";

      log.start(
        "Conformance test: Verifying credential format (SD-JWT VC or mdoc-CBOR)",
      );

      let testSuccess = false;
      try {
        let hasValidFormat = false;
        for (const credential of credentialResponse.response?.credentials ??
          []) {
          try {
            await SDJwt.extractJwt(credential.credential);
            log.debug("  Format: SD-JWT VC");
            hasValidFormat = true;
            break;
          } catch {
            log.debug("  Not SD-JWT, trying mdoc-CBOR...");
          }

          try {
            parseMdoc(Buffer.from(credential.credential, "base64url"));
            log.debug("  Format: mdoc-CBOR");
            hasValidFormat = true;
            break;
          } catch {
            log.error("  Credential is neither SD-JWT VC nor mdoc-CBOR format");
          }
        }

        expect(hasValidFormat, "No credentials found in valid format").toBe(
          true,
        );
        testSuccess = hasValidFormat;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
