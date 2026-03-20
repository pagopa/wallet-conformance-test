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
        external_ta_url: "",
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
    // The orchestrator throws because entityStatementClaims is absent on the failed response
    expect(result.error?.message).toContain("Entity Statement Claims");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataFailure);
    expect(result.pushedAuthorizationRequestResponse).toBeUndefined();
    expect(result.authorizeResponse).toBeUndefined();
    expect(result.tokenResponse).toBeUndefined();
    expect(result.nonceResponse).toBeUndefined();
    expect(result.credentialResponse).toBeUndefined();
  });

  test("step 2 failure — fetchMetadataResponse is populated, PAR response carries the error", async () => {
    // fetchMetadata succeeds with minimal entity statement so the flow can proceed
    const fetchMetadataSuccess = makeStepSuccess({
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
    ).mockResolvedValue(fetchMetadataSuccess);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.pushedAuthorizationRequestStep,
      "run",
    ).mockResolvedValue(parFailure);

    const result = await orchestrator.issuance();

    expect(result.success).toBe(false);
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.walletAttestationResponse).toBeDefined();
    expect(result.pushedAuthorizationRequestResponse).toEqual(parFailure);
    expect(result.authorizeResponse).toBeUndefined();
    expect(result.tokenResponse).toBeUndefined();
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
    // The orchestrator throws because entityStatementClaims is absent on the failed response
    expect(result.error?.message).toContain("Entity Statement Claims");
    expect(result.fetchMetadataResult).toEqual(fetchMetadataFailure);
    expect(result.authorizationRequestResult).toBeUndefined();
    expect(result.redirectUriResult).toBeUndefined();
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
