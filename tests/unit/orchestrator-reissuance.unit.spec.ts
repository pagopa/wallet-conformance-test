/* eslint-disable max-lines-per-function */
/**
 * Unit tests for the Re-Issuance Flow in WalletIssuanceOrchestratorFlow.
 *
 * Verifies that:
 * - reissuance() returns a typed unsuccessful result (without calling
 *   PAR/authorize steps) when no refresh token is configured.
 * - reissuance() runs the refresh-token path when a refresh token is configured.
 * - issuance() is unchanged and never calls reissuance() internally.
 * - reissuance() returns partial responses on token/nonce/credential failures.
 */

import { IssuerTestConfiguration } from "#/config/issuance-test-configuration";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator/wallet-issuance-orchestrator-flow";

// ---------------------------------------------------------------------------
// Module-level mocks
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
      trust_anchor: { port: 3000, ta_url: "http://localhost:3000" },
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
// Helpers
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

const fetchMetadataSuccess = makeStepSuccess({
  discoveredVia: "federation" as const,
  entityStatementClaims: {
    iss: "https://issuer.example.com",
    metadata: {
      oauth_authorization_server: {
        authorization_endpoint: "https://issuer.example.com/authorize",
        pushed_authorization_request_endpoint: "https://issuer.example.com/par",
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

const nonceSuccess = makeStepSuccess({ nonce: { c_nonce: "mock-c-nonce" } });

const credentialSuccess = makeStepSuccess({
  credentials: [{ credential: "mock-credential" }],
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("WalletIssuanceOrchestratorFlow.reissuance()", () => {
  let orchestrator: WalletIssuanceOrchestratorFlow;

  beforeEach(() => {
    vi.clearAllMocks();
    orchestrator = new WalletIssuanceOrchestratorFlow(
      IssuerTestConfiguration.createDefault(),
    );
  });

  test("returns typed unsuccessful result when no refresh token is configured", async () => {
    // PAR, authorize, and token steps must not be called — spy before running
    const parSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    );
    const authorizeSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    );

    // No refresh_token in mock config — reissuance() must fail fast
    const result = await orchestrator.reissuance();

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain(
      "Re-Issuance Flow requires a refresh token",
    );
    expect(parSpy).not.toHaveBeenCalled();
    expect(authorizeSpy).not.toHaveBeenCalled();
  });

  test("runs refresh-token path when refresh_token is configured", async () => {
    // Inject refresh_token into config
    orchestrator.getConfig().issuance.refresh_token_reissuance =
      "my-refresh-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

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
    ).mockResolvedValue(credentialSuccess as never);

    const result = await orchestrator.reissuance();

    expect(result.success).toBe(true);
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toEqual(tokenSuccess);
    expect(result.nonceResponse).toEqual(nonceSuccess);
    expect(result.credentialResponse).toEqual(credentialSuccess);
    // PAR and authorize must not have been called
    expect(result).not.toHaveProperty("pushedAuthorizationRequestResponse");
    expect(result).not.toHaveProperty("authorizeResponse");
  });

  test("token request receives grant_type=refresh_token and not PAR/authorize", async () => {
    orchestrator.getConfig().issuance.refresh_token_reissuance = "test-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    const tokenRunSpy = vi
      .spyOn(
        // @ts-expect-error accessing private field for testing
        orchestrator.tokenRequestStep,
        "run",
      )
      .mockResolvedValue(tokenSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.nonceRequestStep,
      "run",
    ).mockResolvedValue(nonceSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.credentialRequestStep,
      "run",
    ).mockResolvedValue(credentialSuccess as never);

    const parSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    );
    const authorizeSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    );

    await orchestrator.reissuance();

    // PAR and authorize must NOT be called
    expect(parSpy).not.toHaveBeenCalled();
    expect(authorizeSpy).not.toHaveBeenCalled();

    // Token step must be called with refresh_token grant
    expect(tokenRunSpy).toHaveBeenCalledOnce();
    const tokenCallArg = tokenRunSpy.mock.calls[0]?.[0];
    expect(tokenCallArg?.accessTokenRequest).toMatchObject({
      grant_type: "refresh_token",
      refresh_token: "test-token",
    });
  });

  test("issuance() still uses authorization-code flow when refresh_token is set", async () => {
    orchestrator.getConfig().issuance.refresh_token_reissuance =
      "irrelevant-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    const parSpy = vi
      .spyOn(
        // @ts-expect-error accessing private field for testing
        orchestrator.pushedAuthorizationRequestStep,
        "run",
      )
      .mockResolvedValue(
        makeStepSuccess({
          codeVerifier: "mock-code-verifier",
          request_uri: "urn:ietf:params:oauth:request_uri:mock",
        }) as never,
      );

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.authorizeStep,
      "run",
    ).mockResolvedValue(
      makeStepSuccess({
        authorizeResponse: { code: "mock-auth-code" },
        iss: "https://issuer.example.com",
        requestObjectJwt: "mock-request-object-jwt",
      }) as never,
    );

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
    ).mockResolvedValue(credentialSuccess as never);

    const result = await orchestrator.issuance();

    // issuance() should have attempted PAR (it may fail later, but PAR must be tried)
    expect(parSpy).toHaveBeenCalledWith(expect.objectContaining({}));
    // The result must not be the re-issuance response shape
    expect(result).toHaveProperty("pushedAuthorizationRequestResponse");
  });

  test("token failure returns partial response with fetchMetadataResponse and tokenResponse", async () => {
    orchestrator.getConfig().issuance.refresh_token_reissuance =
      "my-refresh-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.tokenRequestStep,
      "run",
    ).mockResolvedValue(makeStepFailure("token endpoint returned 401"));

    const result = await orchestrator.reissuance();

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe("token endpoint returned 401");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toBeDefined();
    expect(result.nonceResponse).toBeUndefined();
    expect(result.credentialResponse).toBeUndefined();
  });

  test("nonce failure returns partial response through tokenResponse", async () => {
    orchestrator.getConfig().issuance.refresh_token_reissuance =
      "my-refresh-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.tokenRequestStep,
      "run",
    ).mockResolvedValue(tokenSuccess as never);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.nonceRequestStep,
      "run",
    ).mockResolvedValue(makeStepFailure("nonce endpoint returned 500"));

    const result = await orchestrator.reissuance();

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe("nonce endpoint returned 500");
    expect(result.tokenResponse).toEqual(tokenSuccess);
    expect(result.nonceResponse).toBeDefined();
    expect(result.credentialResponse).toBeUndefined();
  });

  test("credential failure returns partial response with all prior responses", async () => {
    orchestrator.getConfig().issuance.refresh_token_reissuance =
      "my-refresh-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataSuccess);

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
    ).mockResolvedValue(makeStepFailure("credential endpoint returned 400"));

    const result = await orchestrator.reissuance();

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe("credential endpoint returned 400");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toEqual(tokenSuccess);
    expect(result.nonceResponse).toEqual(nonceSuccess);
    expect(result.credentialResponse).toBeDefined();
  });

  test("never throws — error is always captured in result.error", async () => {
    orchestrator.getConfig().issuance.refresh_token_reissuance =
      "my-refresh-token";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockRejectedValue(new Error("unexpected network error"));

    await expect(orchestrator.reissuance()).resolves.toMatchObject({
      error: expect.objectContaining({ message: "unexpected network error" }),
      success: false,
    });
  });
});
