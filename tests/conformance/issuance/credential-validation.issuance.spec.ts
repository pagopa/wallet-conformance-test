/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import {
  signWithHS256,
  signWithoutClaim,
  signWithPrivateKeyInHeader,
  signWithWrongKey,
  signWithWrongTyp,
  withAlgNoneDPoP,
  withBadSignatureDPoP,
  withCredentialRequestOverrides,
  withCredentialSignJwtOverride,
  withDPoPSignedByWrongKey,
  withNoAthDPoP,
  withNoDPoP,
  withPrivateKeyInDPoPHeader,
  withStaleIatDPoP,
  withWrongAthDPoP,
  withWrongHtmDPoP,
  withWrongHtuDPoP,
  withWrongTypDPoP,
} from "#/helpers/credential-validation-helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { createTokenDPoP } from "@pagopa/io-wallet-oauth2";
import {
  createCredentialRequest,
  CredentialRequestV1_3,
  fetchCredentialResponse,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { decodeJwt } from "@sd-jwt/decode";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

import {
  createKeys,
  fetchWithConfig,
  loadConfigWithHierarchy,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { FetchMetadataStepResponse } from "@/step/issuance";
import {
  CredentialRequestDefaultStep,
  CredentialRequestResponse,
} from "@/step/issuance/credential-request-step";
import { AttestationResponse, RunThroughTokenContext } from "@/types";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("CredentialValidation");

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Request Validation`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let tokenCtx: RunThroughTokenContext;
    let accessToken: string;
    let credentialEndpoint: string;
    let nonceEndpoint: string;
    let credentialIssuer: string;
    let walletAttestationResponse: AttestationResponse;
    let fetchMetadataResponse: FetchMetadataStepResponse;
    let credentialConfigurationId: string;
    let ioWalletSdkConfig: IoWalletSdkConfig;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      credentialConfigurationId = testConfig.credentialConfigurationId;

      baseLog.testSuite({
        profile: testConfig.credentialConfigurationId,
        target: orchestrator.getConfig().issuance.url,
        title: "Credential Request Validation Tests",
      });

      tokenCtx = await orchestrator.runThroughToken();

      ({ credentialIssuer, fetchMetadataResponse, walletAttestationResponse } =
        tokenCtx);

      const entityStatementClaims =
        fetchMetadataResponse.response?.entityStatementClaims;

      const rawAccessToken = tokenCtx.tokenResponse.response?.access_token;
      if (!rawAccessToken) {
        throw new Error(
          "Token step did not return an access_token. Check the token step.",
        );
      }
      accessToken = rawAccessToken;

      const rawCredentialEndpoint =
        entityStatementClaims?.metadata?.openid_credential_issuer
          ?.credential_endpoint;
      if (!rawCredentialEndpoint) {
        throw new Error(
          "Issuer metadata does not contain credential_endpoint.",
        );
      }
      credentialEndpoint = rawCredentialEndpoint;

      const rawNonceEndpoint =
        entityStatementClaims?.metadata?.openid_credential_issuer
          ?.nonce_endpoint;
      if (!rawNonceEndpoint) {
        throw new Error("Issuer metadata does not contain nonce_endpoint.");
      }
      nonceEndpoint = rawNonceEndpoint;

      ioWalletSdkConfig = new IoWalletSdkConfig({
        itWalletSpecsVersion: orchestrator.getConfig().wallet.wallet_version,
      });
    });

    useTestSummary(baseLog, testConfig.name);

    // Restore real timers after each test that might have used fake timers
    afterEach(() => {
      vi.useRealTimers();
    });

    // -----------------------------------------------------------------------
    // Helper: fetch a fresh c_nonce from the issuer
    // -----------------------------------------------------------------------

    async function fetchFreshNonce(): Promise<string> {
      const config = loadConfigWithHierarchy();
      const nonceStep = new testConfig.nonceRequestStepClass(config, baseLog);
      const nonceResponse = await nonceStep.run({ nonceEndpoint });

      const nonce = nonceResponse.response?.nonce as
        | undefined
        | { c_nonce: string };
      if (!nonce?.c_nonce) {
        throw new Error("Failed to obtain c_nonce from nonce endpoint.");
      }
      return nonce.c_nonce;
    }

    // -----------------------------------------------------------------------
    // Helper: run a credential step with a fresh nonce
    // -----------------------------------------------------------------------

    async function runCredentialStep(
      StepClass: typeof CredentialRequestDefaultStep,
    ): Promise<CredentialRequestResponse> {
      const nonce = await fetchFreshNonce();
      const config = loadConfigWithHierarchy();
      const step = new StepClass(config, baseLog);
      return step.run({
        accessToken,
        baseUrl: credentialIssuer,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialIdentifier: credentialConfigurationId,
        credentialRequestEndpoint: credentialEndpoint,
        dPoPKey: tokenCtx.dPoPKey,
        nonce,
        walletAttestation: walletAttestationResponse,
      });
    }

    // -----------------------------------------------------------------------
    // CI_071 — JWT Proof Required Claims
    // -----------------------------------------------------------------------

    test("CI_071: JWT Proof Required Claims | Issuer rejects a credential request whose JWT proof is missing a required claim (nonce)", async () => {
      const log = baseLog.withTag("CI_071");
      const DESCRIPTION =
        "Issuer correctly rejected credential request with missing nonce claim";

      log.start(
        "Conformance test: Verifying JWT proof required claims validation",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with nonce claim removed from proof...",
        );
        const result = await runCredentialStep(
          withCredentialSignJwtOverride(
            testConfig.credentialRequestStepClass,
            signWithoutClaim(
              "nonce",
              walletAttestationResponse.unitKey.privateKey,
              walletAttestationResponse.unitKey.publicKey,
            ),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_072 — Batch JWT Proof Uniqueness
    // -----------------------------------------------------------------------

    test("CI_072: Batch JWT Proof Uniqueness | Issuer rejects a batch credential request with duplicate proof keys", async () => {
      const log = baseLog.withTag("CI_072");
      const DESCRIPTION =
        "Issuer correctly rejected batch credential request with duplicate proof keys";

      log.start(
        "Conformance test: Verifying batch proof uniqueness enforcement",
      );

      let testSuccess = false;
      try {
        const entityStatementClaims =
          fetchMetadataResponse.response?.entityStatementClaims;
        const batchConfig =
          entityStatementClaims?.metadata?.openid_credential_issuer
            ?.batch_credential_issuance;

        if (
          ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0) ||
          !batchConfig
        ) {
          log.debug(
            "→ CI_072 skipped: issuer does not advertise batch_credential_issuance in metadata or wallet config is v1.0 (batch requires => v1.3)",
          );
          testSuccess = true;
          return;
        }

        const nonce = await fetchFreshNonce();
        log.debug("→ Fetched fresh nonce for batch test");

        log.debug(
          "→ Building batch credential request with duplicate proof keys...",
        );
        const duplicateKeyPair = await createKeys();

        // Build a DPoP for the credential endpoint
        const dPoPKey = await createKeys();
        const { jwt: dpop } = await createTokenDPoP({
          accessToken,
          callbacks: {
            ...partialCallbacks,
            signJwt: signJwtCallback([dPoPKey.privateKey]),
          },
          signer: {
            alg: "ES256",
            method: "jwk" as const,
            publicJwk: dPoPKey.publicKey,
          },
          tokenRequest: {
            method: "POST" as const,
            url: credentialEndpoint,
          },
        });

        // Build a v1.3 credential request if possible (batch requires v1.3)
        const batchRequest = await createCredentialRequest({
          callbacks: {
            hash: partialCallbacks.hash,
            signJwt: signJwtCallback([duplicateKeyPair.privateKey]),
          },
          clientId: walletAttestationResponse.unitKey.publicKey.kid,
          config:
            ioWalletSdkConfig as IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>,
          credential_identifier: credentialConfigurationId,
          issuerIdentifier: credentialIssuer,
          keyAttestation: "placeholder-key-attestation",
          nonce,
          signers: [
            {
              alg: "ES256",
              method: "jwk" as const,
              publicJwk: duplicateKeyPair.publicKey,
            },
          ],
        } satisfies Parameters<typeof createCredentialRequest>[0]);

        // Duplicate the proof to create a batch request with same JWK in both proofs
        const { proofs } = batchRequest;
        const batchRequestWithDuplicates = {
          ...batchRequest,
          proofs: { jwt: [proofs.jwt[0], proofs.jwt[0]] },
        } as CredentialRequestV1_3;

        log.debug("→ Sending raw batch request with duplicate proofs...");

        log.debug(
          "→ Validating issuer rejected the duplicate-key batch request...",
        );

        try {
          const response = await fetchCredentialResponse({
            accessToken: accessToken,
            callbacks: { 
              fetch: fetchWithConfig(orchestrator.getConfig().network), 
            },
            credentialEndpoint,
            credentialRequest: batchRequestWithDuplicates,
            dPoP: dpop,
          });
          expect(response).toBeUndefined();

          testSuccess = false;
        } catch (error) {
          log.debug(
            "  Request failed as expected with error: " +
              (error instanceof Error ? error.message : String(error)),
          );
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toMatch(/invalid_proof/i);

          testSuccess = true;
        }
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_073 — Key Proof Type Declaration
    // -----------------------------------------------------------------------

    test("CI_073: Key Proof Type Declaration | Issuer rejects a credential request with an incorrect proof typ header", async () => {
      const log = baseLog.withTag("CI_073");
      const DESCRIPTION =
        "Issuer correctly rejected proof with wrong typ header (JWT instead of openid4vci-proof+jwt)";

      log.start(
        "Conformance test: Verifying proof type declaration validation",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with typ: JWT (wrong value)...",
        );
        const result = await runCredentialStep(
          withCredentialSignJwtOverride(
            testConfig.credentialRequestStepClass,
            signWithWrongTyp(
              "JWT",
              walletAttestationResponse.unitKey.privateKey,
              walletAttestationResponse.unitKey.publicKey,
            ),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_074 — Asymmetric Algorithm
    // -----------------------------------------------------------------------

    test("CI_074: Asymmetric Algorithm | Issuer rejects a credential request whose JWT proof is signed with HS256 (symmetric algorithm)", async () => {
      const log = baseLog.withTag("CI_074");
      const DESCRIPTION =
        "Issuer correctly rejected credential proof signed with HS256";

      log.start("Conformance test: Verifying asymmetric algorithm enforcement");

      let testSuccess = false;
      try {
        log.debug("→ Sending credential request with proof signed by HS256...");
        const result = await runCredentialStep(
          withCredentialSignJwtOverride(
            testConfig.credentialRequestStepClass,
            signWithHS256("conformance-test-hmac-secret"),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected symmetric algorithm...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_075 — Public Key Signature
    // -----------------------------------------------------------------------

    test("CI_075: Public Key Signature | Issuer rejects a credential request whose JWT proof signature does not verify against the declared JWK", async () => {
      const log = baseLog.withTag("CI_075");
      const DESCRIPTION =
        "Issuer correctly rejected proof with mismatched signing key";

      log.start(
        "Conformance test: Verifying proof signature against declared JWK",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with mismatched signing key and JWK header...",
        );
        const result = await runCredentialStep(
          withCredentialSignJwtOverride(
            testConfig.credentialRequestStepClass,
            signWithWrongKey(),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_076 — Private Key Header Exclusion
    // -----------------------------------------------------------------------

    test("CI_076: Private Key Header Exclusion | Issuer rejects a credential request whose JWT proof JWK header contains the private key parameter (d)", async () => {
      const log = baseLog.withTag("CI_076");
      const DESCRIPTION =
        "Issuer correctly rejected proof with private key material in JWK header";

      log.start(
        "Conformance test: Verifying private key exclusion from proof JWK header",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with private key d in proof JWK header...",
        );
        const result = await runCredentialStep(
          withCredentialSignJwtOverride(
            testConfig.credentialRequestStepClass,
            signWithPrivateKeyInHeader(
              walletAttestationResponse.unitKey.privateKey,
            ),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_077 — c_nonce Matching
    // -----------------------------------------------------------------------

    test("CI_077: c_nonce Matching | Issuer rejects a credential request whose proof nonce was not issued by the server", async () => {
      const log = baseLog.withTag("CI_077");
      const DESCRIPTION =
        "Issuer correctly rejected credential request with invalid nonce";

      log.start("Conformance test: Verifying c_nonce matching enforcement");

      let testSuccess = false;
      try {
        const FAKE_NONCE = "this-nonce-was-never-issued-by-the-server";
        log.debug(
          `→ Sending credential request with fake nonce: ${FAKE_NONCE}`,
        );
        const result = await runCredentialStep(
          withCredentialRequestOverrides(
            testConfig.credentialRequestStepClass,
            {
              nonce: FAKE_NONCE,
            },
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the fake nonce...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_078 — JWT Temporal Validity
    // -----------------------------------------------------------------------

    test("CI_078a: JWT Temporal Validity (Future iat) | Issuer rejects a credential proof whose iat is more than the clock-skew tolerance into the future", async () => {
      const log = baseLog.withTag("CI_078a");
      const DESCRIPTION =
        "Issuer correctly rejected credential proof with future iat";

      log.start(
        "Conformance test: Verifying future iat rejection in credential proof",
      );

      let testSuccess = false;
      try {
        log.debug("→ Advancing time 10 minutes into the future...");
        vi.useFakeTimers({ now: Date.now() + 10 * 60 * 1000 });
        log.info("  Time advanced to: " + new Date(Date.now()).toISOString());

        log.debug("→ Sending credential request with future iat in proof...");
        const result = await runCredentialStep(
          testConfig.credentialRequestStepClass,
        );
        log.debug("  Request completed");

        vi.useRealTimers();
        log.debug("→ Time restored");

        log.debug("→ Validating issuer rejected the future iat...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        vi.useRealTimers();
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    /** iat tolerance window is not specified in IT Wallet specs, we set around 5 minutes how defined in PAR specification */
    test("CI_078b: JWT Temporal Validity (Stale iat) | Issuer rejects a credential proof whose iat is more than 5 minutes in the past", async () => {
      const log = baseLog.withTag("CI_078b");
      const DESCRIPTION =
        "Issuer correctly rejected credential proof with stale iat (>5 min)";

      log.start(
        "Conformance test: Verifying stale iat rejection in credential proof",
      );

      let testSuccess = false;
      try {
        log.debug("→ Rewinding time 6 minutes into the past...");
        vi.useFakeTimers({ now: Date.now() - 6 * 60 * 1000 });
        log.debug("  Time set to: " + new Date(Date.now()).toISOString());

        log.debug("→ Sending credential request with stale iat in proof...");
        const result = await runCredentialStep(
          testConfig.credentialRequestStepClass,
        );
        log.debug("  Request completed");

        vi.useRealTimers();
        log.debug("→ Time restored");

        log.debug("→ Validating issuer rejected the stale iat...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        vi.useRealTimers();
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_079 — Credential Registration
    // Note: currwently we support only sd-jwt-vc, planned mdoc with task WLEO-1006
    // -----------------------------------------------------------------------

    test("CI_079: Credential Registration | Issued credential references a valid status list entry initialized as valid", async () => {
      const log = baseLog.withTag("CI_079");
      const DESCRIPTION =
        "Issuer correctly issued credential with status list entry";

      log.start(
        "Conformance test: Verifying credential status list registration",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Running a successful credential request to inspect the response...",
        );
        const result = await runCredentialStep(
          testConfig.credentialRequestStepClass,
        );
        log.debug("  Request completed");

        log.debug("→ Validating credential was successfully issued...");
        expect(result.success).toBe(true);

        const credentials = result.response?.credentials;
        expect(credentials?.length).toBeGreaterThan(0);
        log.debug(`  Credentials received: ${credentials?.length}`);

        log.debug("→ Checking credential for status claim...");
        for (const credentialObj of credentials ?? []) {
          const credentialJwt = credentialObj.credential;
          expect(credentialJwt).toBeDefined();

          const { payload } = decodeJwt(credentialJwt);
          log.debug(
            `  Credential claims: ${JSON.stringify(Object.keys(payload))}`,
          );

          const statusClaim = payload["status"] as
            | Record<string, unknown>
            | undefined;
          expect(
            statusClaim,
            "Credential MUST contain a 'status' claim",
          ).toBeDefined();
          log.debug(`  Status claim present: ${statusClaim !== undefined}`);

          const specVersion = ioWalletSdkConfig.itWalletSpecsVersion;
          if (specVersion === ItWalletSpecsVersion.V1_3) {
            expect(
              statusClaim?.["status_list"],
              "V1.3 MUST contain 'status_list'",
            ).toBeDefined();
            const sl = statusClaim?.["status_list"] as
              | Record<string, unknown>
              | undefined;
            expect(
              typeof sl?.["idx"],
              "'status_list.idx' MUST be a number",
            ).toBe("number");
            expect(
              typeof sl?.["uri"],
              "'status_list.uri' MUST be a string",
            ).toBe("string");

            log.debug(
              "  ✅ Credential contains a status claim referencing a status list",
            );
          } else {
            expect(
              statusClaim?.["status_assertion"],
              "V1.0 MUST contain 'status_assertion'",
            ).toBeDefined();
            const sa = statusClaim?.["status_assertion"] as
              | Record<string, unknown>
              | undefined;
            expect(
              typeof sa?.["credential_hash_alg"],
              "'credential_hash_alg' MUST be a string",
            ).toBe("string");

            log.debug("  ✅ Credential contains a status assertion");
          }
        }

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082 — DPoP Proof and Access Token
    // -----------------------------------------------------------------------

    test("CI_082a: DPoP Proof Missing | Issuer rejects a credential request with no DPoP proof header", async () => {
      const log = baseLog.withTag("CI_082a");
      const DESCRIPTION =
        "Issuer correctly rejected credential request with no DPoP proof";

      log.start("Conformance test: Verifying DPoP proof is required");

      let testSuccess = false;
      try {
        log.debug("→ Sending credential request without a DPoP proof...");
        const result = await runCredentialStep(
          withNoDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_082b: DPoP Wrong htm | Issuer rejects a credential request whose DPoP htm claim is not POST", async () => {
      const log = baseLog.withTag("CI_082b");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with htm=GET (expected POST)";

      log.start("Conformance test: Verifying DPoP htm claim validation");

      let testSuccess = false;
      try {
        log.debug("→ Sending credential request with DPoP htm: GET (wrong)...");
        const result = await runCredentialStep(
          withWrongHtmDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_082c: DPoP Wrong ath | Issuer rejects a credential request whose DPoP ath claim does not match the access token hash", async () => {
      const log = baseLog.withTag("CI_082c");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with incorrect ath claim";

      log.start("Conformance test: Verifying DPoP ath claim validation");

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP ath pointing to wrong access token...",
        );
        const result = await runCredentialStep(
          withWrongAthDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_082d: DPoP Missing ath | Issuer rejects a credential request whose DPoP proof lacks the ath claim (token-endpoint-style DPoP reuse)", async () => {
      const log = baseLog.withTag("CI_082d");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP without ath claim at credential endpoint";

      log.start(
        "Conformance test: Verifying ath claim is mandatory in credential endpoint DPoP",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP missing ath claim (simulating token-endpoint DPoP reuse)...",
        );
        const result = await runCredentialStep(
          withNoAthDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082e — DPoP Wrong typ header (RFC 9449 §4.3 check 4)
    // -----------------------------------------------------------------------

    test("CI_082e: DPoP Wrong typ header | Issuer rejects a credential request whose DPoP typ header is not dpop+jwt", async () => {
      const log = baseLog.withTag("CI_082e");
      const DESCRIPTION =
        'Issuer correctly rejected DPoP with typ="JWT" (expected "dpop+jwt")';

      log.start(
        "Conformance test: Verifying DPoP typ header must be dpop+jwt (RFC 9449 §4.3 check 4)",
      );

      let testSuccess = false;
      try {
        log.debug(
          '→ Sending credential request with DPoP typ: "JWT" (wrong, must be "dpop+jwt")...',
        );
        const result = await runCredentialStep(
          withWrongTypDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082f — DPoP alg=none (RFC 9449 §4.3 check 5)
    // -----------------------------------------------------------------------

    test("CI_082f: DPoP alg=none | Issuer rejects a credential request whose DPoP uses a none algorithm", async () => {
      const log = baseLog.withTag("CI_082f");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with alg=none (symmetric/none algorithms not allowed)";

      log.start(
        "Conformance test: Verifying DPoP algorithm must be asymmetric and not none (RFC 9449 §4.3 check 5)",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP alg: none (wrong, must be asymmetric)...",
        );
        const result = await runCredentialStep(
          withAlgNoneDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082g — DPoP bad signature (RFC 9449 §4.3 check 6)
    // -----------------------------------------------------------------------

    test("CI_082g: DPoP Bad Signature | Issuer rejects a credential request whose DPoP signature does not verify against the declared jwk header key", async () => {
      const log = baseLog.withTag("CI_082g");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with a signature that does not verify against the declared jwk";

      log.start(
        "Conformance test: Verifying DPoP signature must verify against the jwk header key (RFC 9449 §4.3 check 6)",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP signed by key A but declaring key B in jwk header...",
        );
        const result = await runCredentialStep(
          withBadSignatureDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082h — DPoP private key in jwk header (RFC 9449 §4.3 check 7)
    // -----------------------------------------------------------------------

    test("CI_082h: DPoP Private Key in Header | Issuer rejects a credential request whose DPoP jwk header contains private key material", async () => {
      const log = baseLog.withTag("CI_082h");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with private key material (d parameter) in jwk header";

      log.start(
        "Conformance test: Verifying DPoP jwk header must not contain private key material (RFC 9449 §4.3 check 7)",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP jwk header containing the private d parameter...",
        );
        const result = await runCredentialStep(
          withPrivateKeyInDPoPHeader(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082i — DPoP wrong htu (RFC 9449 §4.3 check 9)
    // -----------------------------------------------------------------------

    test("CI_082i: DPoP Wrong htu | Issuer rejects a credential request whose DPoP htu does not match the credential endpoint URI", async () => {
      const log = baseLog.withTag("CI_082i");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with htu pointing to a different URI than the credential endpoint";

      log.start(
        "Conformance test: Verifying DPoP htu must match the HTTP URI of the current request (RFC 9449 §4.3 check 9)",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP htu set to wrong URI...",
        );
        const result = await runCredentialStep(
          withWrongHtuDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_082j — DPoP stale iat (RFC 9449 §4.3 check 11)
    // -----------------------------------------------------------------------

    test("CI_082j: DPoP Stale iat | Issuer rejects a credential request whose DPoP iat is outside the acceptable freshness window", async () => {
      const log = baseLog.withTag("CI_082j");
      const DESCRIPTION =
        "Issuer correctly rejected DPoP with a stale iat (5 minutes in the past)";

      log.start(
        "Conformance test: Verifying DPoP iat must be within the server freshness window (RFC 9449 §4.3 check 11)",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP iat 5 minutes in the past...",
        );
        const result = await runCredentialStep(
          withStaleIatDPoP(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_083 — Key Material PoP
    // -----------------------------------------------------------------------

    test("CI_083: Key Material PoP | Issuer rejects a credential request where the DPoP key differs from the expected proof binding key", async () => {
      const log = baseLog.withTag("CI_083");
      const DESCRIPTION =
        "Issuer correctly rejected credential request where DPoP key ≠ expected proof binding key";

      log.start(
        "Conformance test: Verifying proof key matches DPoP public key",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Sending credential request with DPoP signed by a key different from the proof JWK...",
        );
        const result = await runCredentialStep(
          withDPoPSignedByWrongKey(testConfig.credentialRequestStepClass),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_084a — Credential Type Check
    // -----------------------------------------------------------------------

    test("CI_084a: Credential Type Check | Issuer rejects a credential request for an unknown credential_configuration_id", async () => {
      const log = baseLog.withTag("CI_084a");
      const DESCRIPTION =
        "Issuer correctly rejected credential request for unknown credential type";

      log.start("Conformance test: Verifying credential type validation");

      let testSuccess = false;
      try {
        const UNKNOWN_TYPE =
          "unknown_credential_type_that_does_not_exist_in_issuer_metadata";
        log.debug(
          `→ Sending credential request with credential_identifier: ${UNKNOWN_TYPE}`,
        );
        const result = await runCredentialStep(
          withCredentialRequestOverrides(
            testConfig.credentialRequestStepClass,
            {
              credential_identifier: UNKNOWN_TYPE,
            },
          ),
        );
        log.debug("  Request completed");

        log.debug(
          "→ Validating issuer rejected the unknown credential type...",
        );
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
