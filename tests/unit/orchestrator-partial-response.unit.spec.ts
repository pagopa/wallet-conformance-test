/* eslint-disable max-lines-per-function */
/**
 * Unit tests for partial-response behaviour in orchestrators.
 *
 * Verifies that issuance() and presentation() never throw — on both
 * success and failure they always return a typed result that includes
 * every step response collected before the failure point.
 */

import { IssuerTestConfiguration } from "#/config/issuance-test-configuration";
import { PresentationTestConfiguration } from "#/config/presentation-test-configuration";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator/wallet-issuance-orchestrator-flow";
import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";

// ---------------------------------------------------------------------------
// Module-level mocks — must be hoisted before any imports that use them
// ---------------------------------------------------------------------------

vi.mock("@/logic", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/logic")>();
  return {
    ...actual,
    loadConfigWithHierarchy: vi.fn().mockReturnValue({
      issuance: {
        credential_offer_uri: "",
        credential_types: ["dc_sd_jwt_PersonIdentificationData"],
        save_credential: false,
        url: "https://issuer.example.com",
      },
      logging: {
        log_file: "",
        log_file_format: "json",
        log_format: "pretty",
        log_level: "silent",
      },
      network: { max_retries: 1, timeout: 10, user_agent: "test" },
      presentation: {
        authorize_request_url:
          "https://verifier.example.com/authorize?client_id=https://verifier.example.com",
        verifier: "https://verifier.example.com",
      },
      steps_mapping: { mapping: {} },
      trust: { trust_anchor_entity_configuration_url: "" },
      trust_anchor: {
        port: 3000,
        ta_url: "http://localhost:3000",
      },
      wallet: {
        backup_storage_path: "./backup",
        credentials_storage_path: "./credentials",
        wallet_version: "1.0",
      },
    }),
  };
});

vi.mock("@/functions", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/functions")>();
  return {
    ...actual,
    loadAttestation: vi.fn().mockResolvedValue({
      attestation: "mock-attestation-jwt",
      trustChain: [],
      unitKey: {
        privateKey: { crv: "P-256", d: "mock-d", kty: "EC" },
        publicKey: {
          crv: "P-256",
          kid: "mock-kid",
          kty: "EC",
          x: "mock-x",
          y: "mock-y",
        },
      },
    }),
    loadCredentialsForPresentation: vi.fn().mockResolvedValue([]),
  };
});

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createClientAttestationPopJwt: vi
      .fn()
      .mockResolvedValue("mock-pop-attestation"),
  };
});

// ---------------------------------------------------------------------------
// Helpers — build minimal step response fixtures
// ---------------------------------------------------------------------------

function makeStepFailure(message: string) {
  return {
    durationMs: 10,
    error: new Error(message),
    success: false as const,
  };
}

function makeStepSuccess<T>(response: T) {
  return { durationMs: 10, response, success: true as const };
}

// ---------------------------------------------------------------------------
// Issuance orchestrator tests
// ---------------------------------------------------------------------------

describe("WalletIssuanceOrchestratorFlow.issuance()", () => {
  let orchestrator: WalletIssuanceOrchestratorFlow;

  // Shared fixtures — used across multiple test cases
  const fetchMetadataSuccess = makeStepSuccess({
    discoveredVia: "federation" as const,
    entityStatementClaims: {
      iss: "https://issuer.example.com",
      metadata: {
        oauth_authorization_server: {
          authorization_endpoint: "https://issuer.example.com/authorize",
          pushed_authorization_request_endpoint:
            "https://issuer.example.com/par",
          token_endpoint: "https://issuer.example.com/token",
        },
        openid_credential_issuer: {
          credential_configurations_supported: {
            dc_sd_jwt_PersonIdentificationData: {},
          },
          credential_endpoint: "https://issuer.example.com/credential",
          nonce_endpoint: "https://issuer.example.com/nonce",
        },
      },
      sub: "https://issuer.example.com",
    },
    status: 200,
  });
  const parSuccess = makeStepSuccess({
    codeVerifier: "mock-code-verifier",
    request_uri: "urn:ietf:params:oauth:request_uri:mock",
  });

  beforeEach(async () => {
    vi.clearAllMocks();
    orchestrator = new WalletIssuanceOrchestratorFlow(
      IssuerTestConfiguration.createDefault(),
    );
  });

  test("step 1 failure — returns partial response with only fetchMetadataResponse", async () => {
    const fetchMetadataFailure = makeStepFailure("metadata fetch failed");

    // Stub fetchMetadataStep.run to fail
    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataFailure);

    const result = await orchestrator.issuance();

    expect(result.success).toBe(false);
    // assertStepSuccess now throws the step's own error immediately
    expect(result.error?.message).toContain("metadata fetch failed");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataFailure);
    expect(result.pushedAuthorizationRequestResponse).toBeUndefined();
    expect(result.authorizeResponse).toBeUndefined();
    expect(result.tokenResponse).toBeUndefined();
    expect(result.nonceResponse).toBeUndefined();
    expect(result.credentialResponse).toBeUndefined();
  });

  test("step 2 failure — fetchMetadataResponse is populated, PAR response carries the error", async () => {
    // fetchMetadata succeeds with a minimal entity statement (no token_endpoint needed at this stage)
    const minimalFetchMetadataSuccess = makeStepSuccess({
      discoveredVia: "federation" as const,
      entityStatementClaims: {
        iss: "https://issuer.example.com",
        metadata: {
          oauth_authorization_server: {
            authorization_endpoint: "https://issuer.example.com/authorize",
            pushed_authorization_request_endpoint:
              "https://issuer.example.com/par",
          },
          openid_credential_issuer: {
            credential_configurations_supported: {
              dc_sd_jwt_PersonIdentificationData: {},
            },
            credential_endpoint: "https://issuer.example.com/credential",
            nonce_endpoint: "https://issuer.example.com/nonce",
          },
        },
        sub: "https://issuer.example.com",
      },
      status: 200,
    });
    const parFailure = makeStepFailure("PAR request rejected");

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(minimalFetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    ).mockResolvedValue(parFailure);

    const result = await orchestrator.issuance();

    expect(result.success).toBe(false);
    expect(result.fetchMetadataResponse).toEqual(minimalFetchMetadataSuccess);
    expect(result.walletAttestationResponse).toBeDefined();
    expect(result.pushedAuthorizationRequestResponse).toEqual(parFailure);
    expect(result.authorizeResponse).toBeUndefined();
    expect(result.tokenResponse).toBeUndefined();
  });

  test("step 3 (authorize) failure — returns partial response with success: false", async () => {
    const authorizeFailure = makeStepFailure(
      "authorization server rejected the request",
    );

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    ).mockResolvedValue(parSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    ).mockResolvedValue(authorizeFailure);

    const result = await orchestrator.issuance();

    expect(
      result.success,
      "issuance() must return success: false on authorize step failure",
    ).toBe(false);
    expect(result.error?.message).toBe(
      "authorization server rejected the request",
    );
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.pushedAuthorizationRequestResponse).toEqual(parSuccess);
    expect(result.authorizeResponse).toEqual(authorizeFailure);
    expect(result.tokenResponse).toBeUndefined();
    expect(result.credentialResponse).toBeUndefined();
  });

  test("step 4 (token) failure — returns partial response through authorizeResponse", async () => {
    const authorizeSuccess = makeStepSuccess({
      authorizeResponse: { code: "mock-auth-code" },
      requestObject: { response_uri: "https://issuer.example.com/redirect" },
    });
    const tokenFailure = makeStepFailure("token endpoint returned 401");

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    ).mockResolvedValue(parSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    ).mockResolvedValue(authorizeSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.tokenRequestStep,
      "run",
    ).mockResolvedValue(tokenFailure);

    const result = await orchestrator.issuance();

    expect(
      result.success,
      "issuance() must return success: false on token step failure",
    ).toBe(false);
    expect(result.error?.message).toBe("token endpoint returned 401");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.pushedAuthorizationRequestResponse).toEqual(parSuccess);
    expect(result.authorizeResponse).toEqual(authorizeSuccess);
    expect(
      result.tokenResponse,
      "tokenResponse must be populated even on failure",
    ).toEqual(tokenFailure);
    expect(result.nonceResponse).toBeUndefined();
    expect(result.credentialResponse).toBeUndefined();
  });

  test("step 5 (nonce) failure — returns partial response through tokenResponse", async () => {
    const authorizeSuccess = makeStepSuccess({
      authorizeResponse: { code: "mock-auth-code" },
      requestObject: { response_uri: "https://issuer.example.com/redirect" },
    });
    const tokenSuccess = makeStepSuccess({
      access_token: "mock-access-token",
      dPoPKey: {
        privateKey: { crv: "P-256", d: "mock-d", kty: "EC" },
        publicKey: {
          crv: "P-256",
          kid: "mock-kid",
          kty: "EC",
          x: "mock-x",
          y: "mock-y",
        },
      },
    });
    const nonceFailure = makeStepFailure("nonce endpoint returned 500");

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    ).mockResolvedValue(parSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    ).mockResolvedValue(authorizeSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.tokenRequestStep,
      "run",
    ).mockResolvedValue(tokenSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.nonceRequestStep,
      "run",
    ).mockResolvedValue(nonceFailure);

    const result = await orchestrator.issuance();

    expect(
      result.success,
      "issuance() must return success: false on nonce step failure",
    ).toBe(false);
    expect(result.error?.message).toBe("nonce endpoint returned 500");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toEqual(tokenSuccess);
    expect(
      result.nonceResponse,
      "nonceResponse must be populated even on failure",
    ).toEqual(nonceFailure);
    expect(result.credentialResponse).toBeUndefined();
  });

  test("step 6 (credential) failure — returns partial response with success: false and credentialResponse populated", async () => {
    const authorizeSuccess = makeStepSuccess({
      authorizeResponse: { code: "mock-auth-code" },
      requestObject: { response_uri: "https://issuer.example.com/redirect" },
    });
    const tokenSuccess = makeStepSuccess({
      access_token: "mock-access-token",
      dPoPKey: {
        privateKey: { crv: "P-256", d: "mock-d", kty: "EC" },
        publicKey: {
          crv: "P-256",
          kid: "mock-kid",
          kty: "EC",
          x: "mock-x",
          y: "mock-y",
        },
      },
    });
    const nonceSuccess = makeStepSuccess({
      nonce: { c_nonce: "mock-c-nonce" },
    });
    const credentialFailure = makeStepFailure(
      "credential endpoint returned 400",
    );

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    ).mockResolvedValue(parSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    ).mockResolvedValue(authorizeSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.tokenRequestStep,
      "run",
    ).mockResolvedValue(tokenSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.nonceRequestStep,
      "run",
    ).mockResolvedValue(nonceSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.credentialRequestStep,
      "run",
    ).mockResolvedValue(credentialFailure);

    const result = await orchestrator.issuance();

    expect(
      result.success,
      "issuance() must return success: false on credential step failure",
    ).toBe(false);
    expect(result.error?.message).toBe("credential endpoint returned 400");
    expect(
      result.credentialResponse,
      "credentialResponse must be populated even on failure",
    ).toEqual(credentialFailure);
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toBeDefined();
    expect(result.nonceResponse).toEqual(nonceSuccess);
  });

  test("never throws — error is captured in result.error", async () => {
    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockRejectedValue(new Error("unexpected network error"));

    await expect(orchestrator.issuance()).resolves.toMatchObject({
      error: expect.objectContaining({ message: "unexpected network error" }),
      success: false,
    });
  });
});

// ---------------------------------------------------------------------------
// Presentation orchestrator tests
// ---------------------------------------------------------------------------

describe("WalletPresentationOrchestratorFlow.presentation()", () => {
  let orchestrator: WalletPresentationOrchestratorFlow;

  beforeEach(async () => {
    vi.clearAllMocks();
    orchestrator = new WalletPresentationOrchestratorFlow(
      PresentationTestConfiguration.createDefault(),
    );
  });

  test("step 1 failure — returns partial response with only fetchMetadataResult", async () => {
    const fetchMetadataFailure = makeStepFailure(
      "verifier metadata unreachable",
    );

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataFailure);

    const result = await orchestrator.presentation();

    expect(result.success).toBe(false);
    // assertStepSuccess now throws the step's own error immediately
    expect(result.error?.message).toContain("verifier metadata unreachable");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataFailure);
    expect(result.authorizationRequestResponse).toBeUndefined();
    expect(result.redirectUriResponse).toBeUndefined();
  });

  test("step 2 (authorizationRequest) failure — fetchMetadataResponse populated, authorizationRequestResponse carries error", async () => {
    const fetchMetadataSuccess = makeStepSuccess({
      discoveredVia: "federation" as const,
      entityStatementClaims: {
        iss: "https://verifier.example.com",
        metadata: {
          openid_credential_verifier: {
            authorization_endpoint: "https://verifier.example.com/authorize",
          },
        },
        sub: "https://verifier.example.com",
      },
      status: 200,
    });
    const authorizationRequestFailure = makeStepFailure(
      "verifier rejected the authorization request",
    );

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizationRequestStep,
      "run",
    ).mockResolvedValue(authorizationRequestFailure);

    const result = await orchestrator.presentation();

    expect(
      result.success,
      "presentation() must return success: false on authorizationRequest step failure",
    ).toBe(false);
    expect(result.error?.message).toBe(
      "verifier rejected the authorization request",
    );
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(
      result.authorizationRequestResponse,
      "authorizationRequestResponse must be populated even on failure",
    ).toEqual(authorizationRequestFailure);
    expect(result.redirectUriResponse).toBeUndefined();
  });

  test("step 3 (redirectUri) failure — authorizationRequestResult populated, redirectUriResult carries error", async () => {
    const fetchMetadataSuccess = makeStepSuccess({
      discoveredVia: "federation" as const,
      entityStatementClaims: {
        iss: "https://verifier.example.com",
        metadata: {
          openid_credential_verifier: {
            authorization_endpoint: "https://verifier.example.com/authorize",
          },
        },
        sub: "https://verifier.example.com",
      },
      status: 200,
    });
    const authorizationRequestSuccess = makeStepSuccess({
      authorizationResponse: { state: "mock-state", vp_token: "mock-vp" },
      responseUri: "https://verifier.example.com/response",
    });
    const redirectUriFailure = makeStepFailure(
      "redirect URI endpoint returned 400",
    );

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizationRequestStep,
      "run",
    ).mockResolvedValue(authorizationRequestSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.redirectUriStep,
      "run",
    ).mockResolvedValue(redirectUriFailure);

    const result = await orchestrator.presentation();

    expect(
      result.success,
      "presentation() must return success: false on redirectUri step failure",
    ).toBe(false);
    expect(result.error?.message).toBe("redirect URI endpoint returned 400");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.authorizationRequestResponse).toEqual(
      authorizationRequestSuccess,
    );
    expect(
      result.redirectUriResponse,
      "redirectUriResult must be populated even on failure",
    ).toEqual(redirectUriFailure);
  });

  test("never throws — error is captured in result.error", async () => {
    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockRejectedValue(new Error("TLS handshake failed"));

    await expect(orchestrator.presentation()).resolves.toMatchObject({
      error: expect.objectContaining({ message: "TLS handshake failed" }),
      success: false,
    });
  });
});
