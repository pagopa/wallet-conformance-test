/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import {
  buildTamperedPopJwt,
  createFakeAttestationResponse,
  signThenTamperPayload,
  signWithCustomIss,
  signWithHS256,
  signWithMismatchedAlgorithm,
  signWithWrongKey,
  signWithWrongKid,
  withParOverrides,
  withSignJwtOverride,
} from "#/helpers/par-validation-helpers";
import {
  createClientAttestationPopJwt,
  createPushedAuthorizationRequest,
  fetchPushedAuthorizationResponse,
  type PushedAuthorizationRequest,
} from "@pagopa/io-wallet-oauth2";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";


import {
  createLogger,
  createQuietLogger,
  loadConfigWithHierarchy,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { PushedAuthorizationRequestDefaultStep } from "@/step/issuance";
import { PushedAuthorizationRequestResponse } from "@/step/issuance/pushed-authorization-request-step";
import { AttestationResponse } from "@/types";

// ---------------------------------------------------------------------------
// Module-level test registration
// ---------------------------------------------------------------------------

const testConfigs = await defineIssuanceTest("PARValidation");

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] PAR Request Object Validation`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let walletAttestationResponse: AttestationResponse;
    let pushedAuthorizationRequestEndpoint: string;
    let authorizationServer: string;
    let credentialIssuer: string;

    // -----------------------------------------------------------------------
    // Shared setup – run once per credential type
    // -----------------------------------------------------------------------

    beforeAll(async () => {
      baseLog.testSuite({
        profile: testConfig.credentialConfigurationId,
        target: orchestrator.getConfig().issuance.url,
        title: "PAR Request Object Validation Tests",
      });

      // Run through the flow up to the PAR step to extract necessary context for the tests
      const ctx = await orchestrator.runThroughPar();

      walletAttestationResponse = ctx.walletAttestationResponse;
      authorizationServer = ctx.authorizationServer;
      pushedAuthorizationRequestEndpoint =
        ctx.pushedAuthorizationRequestEndpoint;
      credentialIssuer = ctx.credentialIssuer;
    });

    // Restore real timers after each test that might have used fake timers
    afterEach(() => {
      vi.useRealTimers();
    });

    // -----------------------------------------------------------------------
    // Helper: create a fresh popAttestation JWT (avoids 60 s TTL exhaustion)
    // -----------------------------------------------------------------------

    async function createFreshPop(): Promise<string> {
      return createClientAttestationPopJwt({
        authorizationServer,
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([
            walletAttestationResponse.unitKey.privateKey,
          ]),
        },
        clientAttestation: walletAttestationResponse.attestation,
      });
    }

    // -----------------------------------------------------------------------
    // Helper: run a PAR step with optional walletAttestation override.
    // Uses a quiet logger so step-internal traces don't pollute test output.
    // -----------------------------------------------------------------------

    async function runParStep(
      StepClass: typeof PushedAuthorizationRequestDefaultStep,
      attestationOverride?: Omit<AttestationResponse, "created">,
    ): Promise<PushedAuthorizationRequestResponse> {
      const config = loadConfigWithHierarchy();
      const freshPop = await createFreshPop();
      const step = new StepClass(config, createQuietLogger());
      return step.run({
        baseUrl: config.issuance.url,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialConfigurationIds: [testConfig.credentialConfigurationId],
        popAttestation: freshPop,
        pushedAuthorizationRequestEndpoint,
        walletAttestation: attestationOverride ?? walletAttestationResponse,
      });
    }

    // -----------------------------------------------------------------------
    // CI_015 — Request Object Signature Validation
    // -----------------------------------------------------------------------

    test("CI_015: Request Object Signature Validation | Issuer rejects a PAR signed with a key that does not match the wallet attestation", async () => {
      const log = baseLog.withTag("CI_015");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with invalid signature";

      log.start(
        "Conformance test: Verifying PAR request object signature validation",
      );

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request signed with wrong key...");
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
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
    // CI_015a — Algorithm Header Processing (RFC 9126/9101)
    // -----------------------------------------------------------------------

    test("CI_015a: Algorithm Header Processing | Issuer uses the alg header to validate the Request Object signature (RFC 9126/9101)", async () => {
      const log = baseLog.withTag("CI_015a");
      const DESCRIPTION =
        "Issuer correctly used alg header (ES256) for validation and rejected the PAR";

      log.start(
        "Conformance test: Verifying issuer uses alg header for signature validation",
      );

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request with mismatched algorithm...");
        log.debug("  Header declares: alg=ES256 (permitted)");
        log.debug("  Actually signed with: ES384");
        log.debug(
          "  If issuer correctly uses alg from header → validation fails",
        );
        log.debug(
          "  If issuer ignores header and infers from key → validation might succeed (incorrect behavior)",
        );

        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signWithMismatchedAlgorithm("ES256", "ES384"),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);
        log.debug("     This confirms compliance with RFC 9126/9101");

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_015b — Wallet Attestation Public Key Retrieval
    // -----------------------------------------------------------------------

    test("CI_015b: Wallet Attestation Public Key Retrieval | Issuer rejects a PAR when the wallet attestation references an unregistered key not in the trust chain", async () => {
      const log = baseLog.withTag("CI_015b");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with untrusted attestation";

      log.start(
        "Conformance test: Verifying wallet attestation public key retrieval",
      );

      let testSuccess = false;
      try {
        log.debug(
          "→ Creating fake wallet attestation with unregistered key...",
        );
        const fakeAttestation = await createFakeAttestationResponse();
        log.debug("  Fake attestation created");

        log.debug("→ Sending PAR request with fake attestation...");
        const result = await runParStep(
          testConfig.pushedAuthorizationRequestStepClass,
          fakeAttestation,
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
    // CI_015c — JWT Key Identifier Reference
    // -----------------------------------------------------------------------

    test("CI_015c: JWT Key Identifier Reference | Issuer rejects a PAR whose kid header does not match the wallet attestation public key kid", async () => {
      const log = baseLog.withTag("CI_015c");
      const DESCRIPTION = "Issuer correctly rejected PAR with wrong kid";

      log.start("Conformance test: Verifying JWT key identifier reference");

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request with wrong kid header...");
        log.debug("  kid: wrong-kid-that-does-not-match");
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signWithWrongKid(
              "wrong-kid-that-does-not-match",
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
    // CI_015d — Cryptographic Signature Integrity
    // -----------------------------------------------------------------------

    test("CI_015d: Cryptographic Signature Integrity | Issuer rejects a PAR whose request JWT payload was tampered after signing", async () => {
      const log = baseLog.withTag("CI_015d");
      const DESCRIPTION = "Issuer correctly rejected PAR with tampered payload";

      log.start(
        "Conformance test: Verifying cryptographic signature integrity",
      );

      let testSuccess = false;
      try {
        log.debug("→ Creating PAR request with tampered payload...");
        log.debug("  Tampering field: aud");
        log.debug("  Tampered value: https://tampered.example.com");
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signThenTamperPayload(
              walletAttestationResponse.unitKey.privateKey,
              walletAttestationResponse.unitKey.publicKey,
              "aud",
              "https://tampered.example.com",
            ),
          ),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the tampered request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_019 — Algorithm Compliance Check
    // -----------------------------------------------------------------------

    test("CI_019: Algorithm Compliance Check | Issuer rejects a PAR signed with HS256 (symmetric algorithm not allowed by spec)", async () => {
      const log = baseLog.withTag("CI_019");
      const DESCRIPTION = "Issuer correctly rejected PAR with HS256 signature";

      log.start(
        "Conformance test: Verifying algorithm compliance (asymmetric only)",
      );

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request signed with HS256...");
        log.debug("  Algorithm: HS256 (symmetric, not allowed)");
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signWithHS256("conformance-test-hmac-value"),
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
    // CI_020 — Client ID Consistency
    // -----------------------------------------------------------------------

    test("CI_020: Client ID Consistency | Issuer rejects a PAR whose client_id in the POST body does not match the JWT claim", async () => {
      const log = baseLog.withTag("CI_020");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with client_id mismatch";

      log.start(
        "Conformance test: Verifying client_id consistency between POST body and JWT",
      );

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request with mismatched client_id...");
        log.debug(
          "  client_id in POST body: mallory_client_id_that_does_not_match",
        );
        const result = await runParStep(
          withParOverrides(testConfig.pushedAuthorizationRequestStepClass, {
            clientId: "mallory_client_id_that_does_not_match",
          }),
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
    // CI_021 — Issuer-Client ID Matching
    // -----------------------------------------------------------------------

    test("CI_021: Issuer-Client ID Matching | Issuer rejects a PAR whose JWT iss claim does not match client_id", async () => {
      const log = baseLog.withTag("CI_021");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with iss/client_id mismatch";

      log.start("Conformance test: Verifying iss claim matches client_id");

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request with custom iss claim...");
        log.debug("  iss claim: https://attacker.example.com");
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signWithCustomIss(
              "https://attacker.example.com",
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
    // CI_022 — Audience Claim Verification
    // -----------------------------------------------------------------------

    test("CI_022: Audience Claim Verification | Issuer rejects a PAR whose aud claim does not match its own issuer identifier", async () => {
      const log = baseLog.withTag("CI_022");
      const DESCRIPTION = "Issuer correctly rejected PAR with wrong audience";

      log.start(
        "Conformance test: Verifying audience claim matches issuer identifier",
      );

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request with wrong audience...");
        log.debug("  aud claim: https://wrong.example.com");
        const result = await runParStep(
          withParOverrides(testConfig.pushedAuthorizationRequestStepClass, {
            audience: "https://wrong.example.com",
          }),
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
    // CI_023 — Request URI Parameter Rejection
    // -----------------------------------------------------------------------

    test("CI_023: Request URI Parameter Rejection | Issuer rejects a PAR request that includes a request_uri parameter in the POST body", async () => {
      const log = baseLog.withTag("CI_023");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with request_uri parameter";

      log.start(
        "Conformance test: Verifying request_uri parameter is rejected in PAR",
      );

      let testSuccess = false;
      try {
        log.debug("→ Building PAR request with request_uri parameter...");
        // Build a normal PAR request, then use a custom fetch that injects
        // `request_uri` into the POST body before sending.
        // RFC 9126 §2.1 prohibits mixing `request` and `request_uri` in the same PAR call.
        const config = loadConfigWithHierarchy();

        const parOptions = {
          audience: config.issuance.url,
          authorization_details: [
            {
              credential_configuration_id: testConfig.credentialConfigurationId,
              type: "openid_credential" as const,
            },
          ],
          callbacks: {
            generateRandom: partialCallbacks.generateRandom,
            hash: partialCallbacks.hash,
            signJwt: signJwtCallback([
              walletAttestationResponse.unitKey.privateKey,
            ]),
          },
          clientId: walletAttestationResponse.unitKey.publicKey.kid,
          codeChallengeMethodsSupported: ["S256"],
          dpop: {
            signer: {
              alg: "ES256" as const,
              method: "jwk" as const,
              publicJwk: walletAttestationResponse.unitKey.publicKey,
            },
          },
          pkceCodeVerifier: "example_code_verifier",
          redirectUri: "https://client.example.org/cb",
          responseMode: "query",
        };

        const signed: PushedAuthorizationRequest =
          await createPushedAuthorizationRequest(parOptions);
        log.debug("  PAR request created");

        log.debug("→ Injecting request_uri into POST body...");
        log.debug(
          "  request_uri: urn:ietf:params:oauth:request_uri:ci-023-test",
        );
        // Custom fetch that injects request_uri into the form-encoded POST body
        // Capture original fetch to prevent infinite recursion if fetch is monkey-patched
        const originalFetch = fetch;
        const customFetch: typeof fetch = async (input, init) => {
          if (init?.body != null) {
            const params = new URLSearchParams(init.body.toString());
            params.set(
              "request_uri",
              "urn:ietf:params:oauth:request_uri:ci-023-test",
            );
            return originalFetch(input, { ...init, body: params.toString() });
          }
          return originalFetch(input, init);
        };

        let rejected = false;
        try {
          log.debug("→ Sending PAR request with request_uri...");
          await fetchPushedAuthorizationResponse({
            callbacks: { fetch: customFetch },
            clientAttestationDPoP: await createFreshPop(),
            pushedAuthorizationRequest: signed,
            pushedAuthorizationRequestEndpoint,
            walletAttestation: walletAttestationResponse.attestation,
          });
          log.debug("  Request completed without error (unexpected)");
        } catch {
          rejected = true;
          log.debug("  Request rejected as expected");
        }

        log.debug("→ Validating issuer rejected the request...");
        expect(rejected).toBe(true);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_024 — Mandatory Parameters
    // -----------------------------------------------------------------------

    test("CI_024: Mandatory Parameters | Issuer returns an error when required PAR parameters are absent (missing redirectUri)", async () => {
      const log = baseLog.withTag("CI_024");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with missing redirectUri";

      log.start(
        "Conformance test: Verifying mandatory PAR parameters are enforced",
      );

      let testSuccess = false;
      try {
        log.debug("→ Sending PAR request without redirectUri...");
        const result = await runParStep(
          withParOverrides(testConfig.pushedAuthorizationRequestStepClass, {
            // Intentionally cast: we need to send an absent redirectUri to verify
            // the issuer enforces this mandatory parameter (CI_024).
            redirectUri: undefined as unknown as string,
          }),
        );
        log.debug("  Request completed");

        log.debug("→ Validating issuer returned an error...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_025 — Token Expiration
    // -----------------------------------------------------------------------

    test("CI_025: Token Expiration | Issuer rejects a PAR request object whose exp claim is in the past", async () => {
      const log = baseLog.withTag("CI_025");
      const DESCRIPTION = "Issuer correctly rejected PAR with expired token";

      log.start("Conformance test: Verifying token expiration validation");

      let testSuccess = false;
      try {
        log.debug("→ Freezing time 10 minutes in the past...");
        // Freeze time 10 minutes in the past so the SDK generates an already-expired JWT
        vi.useFakeTimers({ now: Date.now() - 10 * 60 * 1000 });
        log.debug("  Time frozen at: " + new Date(Date.now()).toISOString());

        log.debug("→ Sending PAR request with expired token...");
        const result = await runParStep(
          testConfig.pushedAuthorizationRequestStepClass,
        );
        log.debug("  Request completed");

        vi.useRealTimers();
        log.debug("→ Time restored");

        log.debug("→ Validating issuer rejected the expired token...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        vi.useRealTimers();
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_026 — Token Issuance Time (Future iat)
    // -----------------------------------------------------------------------

    test("CI_026: Token Issuance Time (Future iat) | Issuer rejects a PAR whose iat is more than the clock-skew tolerance into the future", async () => {
      const log = baseLog.withTag("CI_026");
      const DESCRIPTION = "Issuer correctly rejected PAR with future iat";

      log.start(
        "Conformance test: Verifying future iat validation with clock-skew tolerance",
      );

      let testSuccess = false;
      try {
        log.debug("→ Advancing time 10 minutes into the future...");
        // Advance the clock 10 minutes forward so iat > server_now + tolerance
        vi.useFakeTimers({ now: Date.now() + 10 * 60 * 1000 });
        log.debug("  Time advanced to: " + new Date(Date.now()).toISOString());

        log.debug("→ Sending PAR request with future iat...");
        const result = await runParStep(
          testConfig.pushedAuthorizationRequestStepClass,
        );
        log.debug("  Request completed");

        vi.useRealTimers();
        log.debug("→ Time restored");

        log.debug("→ Validating issuer rejected the future iat...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_026a — PAR Token Time Rejection (Stale iat)
    // -----------------------------------------------------------------------

    test("CI_026a: PAR Token Time Rejection (Stale iat) | Issuer rejects a PAR whose iat is more than 5 minutes in the past", async () => {
      const log = baseLog.withTag("CI_026a");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with stale iat (>5 min)";

      log.start(
        "Conformance test: Verifying stale iat rejection (5-minute window)",
      );

      let testSuccess = false;
      try {
        log.debug("→ Rewinding time 6 minutes into the past...");
        // Go back 6 minutes so iat exceeds the 5-minute clock-skew window
        vi.useFakeTimers({ now: Date.now() - 6 * 60 * 1000 });
        log.debug("  Time set to: " + new Date(Date.now()).toISOString());

        log.debug("→ Sending PAR request with stale iat...");
        const result = await runParStep(
          testConfig.pushedAuthorizationRequestStepClass,
        );
        log.debug("  Request completed");

        vi.useRealTimers();
        log.debug("→ Time restored");

        log.debug("→ Validating issuer rejected the stale iat...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // Helper: run a PAR step with an optional custom popAttestation override.
    // Uses a quiet logger so step-internal traces don't pollute test output.
    // -----------------------------------------------------------------------

    async function runParStepWithCustomPop(
      customPopAttestation: string,
    ): Promise<PushedAuthorizationRequestResponse> {
      const config = loadConfigWithHierarchy();
      const step = new testConfig.pushedAuthorizationRequestStepClass(
        config,
        createQuietLogger(),
      );
      return step.run({
        baseUrl: credentialIssuer,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialConfigurationIds: [testConfig.credentialConfigurationId],
        popAttestation: customPopAttestation,
        pushedAuthorizationRequestEndpoint,
        walletAttestation: walletAttestationResponse,
      });
    }

    // -----------------------------------------------------------------------
    // CI_027 — Replay Attack Prevention
    // -----------------------------------------------------------------------

    test("CI_027: Replay Attack Prevention | Issuer rejects a second PAR request that reuses an already-seen jti", async () => {
      const log = baseLog.withTag("CI_027");
      const DESCRIPTION = "Issuer correctly rejected replayed jti";

      log.start("Conformance test: Verifying jti replay attack prevention");

      let testSuccess = false;
      try {
        const FIXED_JTI = `conformance-test-jti-${crypto.randomUUID()}`;
        log.debug("→ Creating PAR step with fixed jti...");
        log.debug(`  jti: ${FIXED_JTI}`);

        const StepClass = withParOverrides(
          testConfig.pushedAuthorizationRequestStepClass,
          { jti: FIXED_JTI },
        );

        // First request — should succeed (server caches the jti)
        log.debug("→ Sending first PAR request...");
        const firstResult = await runParStep(StepClass);
        log.debug(
          `  First request result: ${firstResult.success ? "success" : "failed"}`,
        );
        expect(firstResult.success).toBe(true);
        log.debug("  First request succeeded (jti cached by server)");

        // Second request with the same jti — server must reject it
        log.debug("→ Sending second PAR request with same jti...");
        const secondResult = await runParStep(StepClass);
        log.debug(
          `  Second request result: ${secondResult.success ? "success" : "failed"}`,
        );
        log.debug("→ Validating issuer rejected the replay...");
        expect(secondResult.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    // -----------------------------------------------------------------------
    // CI_028 — OAuth-Client-Attestation-PoP Validation
    // -----------------------------------------------------------------------

    test("CI_028a: PoP Wrong Signing Key | Issuer rejects a PAR whose OAuth-Client-Attestation-PoP is signed with a key that does not match cnf.jwk in the wallet attestation", async () => {
      const log = baseLog.withTag("CI_028a");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with wrong PoP signing key";

      log.start(
        "Conformance test: PoP signed with wrong key rejected (CI_028 §5)",
      );

      let testSuccess = false;
      try {
        log.debug("→ Building PoP signed with a fresh random key...");
        const tamperedPop = await buildTamperedPopJwt({
          authorizationServer,
          clientAttestation: walletAttestationResponse.attestation,
          realUnitKey: walletAttestationResponse.unitKey.privateKey,
          useWrongKey: true,
        });
        log.debug("  Tampered PoP created");

        log.debug("→ Sending PAR request with tampered PoP...");
        const result = await runParStepWithCustomPop(tamperedPop);
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_028b: PoP Wrong Audience | Issuer rejects a PAR whose OAuth-Client-Attestation-PoP aud claim does not match the issuer identifier", async () => {
      const log = baseLog.withTag("CI_028b");
      const DESCRIPTION =
        "Issuer correctly rejected PAR with wrong PoP audience";

      log.start(
        "Conformance test: PoP with wrong aud claim rejected (CI_028 §5)",
      );

      let testSuccess = false;
      try {
        log.debug("→ Building PoP with wrong aud claim...");
        log.debug("  aud: https://attacker.example.com");
        const tamperedPop = await buildTamperedPopJwt({
          authorizationServer,
          clientAttestation: walletAttestationResponse.attestation,
          realUnitKey: walletAttestationResponse.unitKey.privateKey,
          wrongAud: "https://attacker.example.com",
        });
        log.debug("  Tampered PoP created");

        log.debug("→ Sending PAR request with wrong-aud PoP...");
        const result = await runParStepWithCustomPop(tamperedPop);
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the request...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });

    test("CI_028c: PoP Expired | Issuer rejects a PAR whose OAuth-Client-Attestation-PoP exp is in the past", async () => {
      const log = baseLog.withTag("CI_028c");
      const DESCRIPTION = "Issuer correctly rejected PAR with expired PoP";

      log.start("Conformance test: Expired PoP rejected (CI_028 §5)");

      let testSuccess = false;
      try {
        log.debug("→ Building PoP with exp 10 minutes in the past...");
        const pastIssuedAt = new Date(Date.now() - 11 * 60 * 1000);
        const pastExpiresAt = new Date(Date.now() - 10 * 60 * 1000);
        const tamperedPop = await buildTamperedPopJwt({
          authorizationServer,
          clientAttestation: walletAttestationResponse.attestation,
          expiresAt: pastExpiresAt,
          issuedAt: pastIssuedAt,
          realUnitKey: walletAttestationResponse.unitKey.privateKey,
        });
        log.debug("  Expired PoP created");

        log.debug("→ Sending PAR request with expired PoP...");
        const result = await runParStepWithCustomPop(tamperedPop);
        log.debug("  Request completed");

        log.debug("→ Validating issuer rejected the expired PoP...");
        expect(result.success).toBe(false);

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    });
  });
});
