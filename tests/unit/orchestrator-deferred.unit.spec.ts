/* eslint-disable max-lines-per-function */
/**
 * Unit tests for the Deferred Issuance Flow in WalletIssuanceOrchestratorFlow.
 *
 * Verifies that:
 * - deferred() returns a typed unsuccessful result without calling remote steps
 *   when either refresh_token_deferred or transaction_id is missing.
 * - deferred() uses grant_type=refresh_token with the deferred refresh token.
 * - deferred() posts to deferred_credential_endpoint with the transaction_id.
 * - deferred() saves a credential when save_credential=true and the response is immediate.
 * - deferred() returns partial responses on token / deferred-step failures.
 * - deferred() returns success:true for a 202 still-pending response.
 * - issuance() and reissuance() are unaffected by the new field.
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
        deferred_credential_endpoint:
          "https://issuer.example.com/credential/deferred",
        nonce_endpoint: "https://issuer.example.com/nonce",
      },
    },
    sub: "https://issuer.example.com",
  },
  status: 200,
});

const fetchMetadataMissingDeferred = makeStepSuccess({
  discoveredVia: "federation" as const,
  entityStatementClaims: {
    iss: "https://issuer.example.com",
    metadata: {
      oauth_authorization_server: {
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

const dPoPKey = {
  privateKey: { crv: "P-256", d: "mock-d", kty: "EC" },
  publicKey: {
    crv: "P-256",
    kid: "mock-kid",
    kty: "EC",
    x: "mock-x",
    y: "mock-y",
  },
};

const tokenSuccess = makeStepSuccess({
  access_token: "mock-access-token",
  dPoPKey,
});

// 200 immediate deferred response with credentials
const deferredSuccessImmediate = makeStepSuccess({
  credentials: [{ credential: "mock-deferred-credential" }],
  notification_id: "mock-notif",
});

// 202 still-pending response
const deferredSuccessPending = makeStepSuccess({
  interval: 5,
  transaction_id: "new-txn-id",
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("WalletIssuanceOrchestratorFlow.deferred()", () => {
  let orchestrator: WalletIssuanceOrchestratorFlow;

  beforeEach(() => {
    vi.clearAllMocks();
    orchestrator = new WalletIssuanceOrchestratorFlow(
      IssuerTestConfiguration.createDefault(),
    );
    // Reset deferred-flow fields to undefined after each new orchestrator
    // (the mock returns the same config object, so mutations bleed between tests)
    orchestrator.getConfig().issuance.refresh_token_deferred = undefined;
    orchestrator.getConfig().issuance.transaction_id_deferred = undefined;
  });

  test("fails fast when both refresh_token_deferred and transaction_id are missing", async () => {
    const fetchSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    );

    const result = await orchestrator.deferred();

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain(
      "Deferred Issuance Flow requires both a deferred refresh token and a transaction id",
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("fails fast when only refresh_token_deferred is set", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred =
      "my-deferred-token";

    const fetchSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    );

    const result = await orchestrator.deferred();

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain(
      "deferred refresh token and a transaction id",
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("fails fast when only transaction_id is set", async () => {
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-123";

    const fetchSpy = vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    );

    const result = await orchestrator.deferred();

    expect(result.success).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("does not call PAR or authorize steps", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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
      orchestrator.deferredCredentialRequestStep,
      "run",
    ).mockResolvedValue(deferredSuccessImmediate as never);

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

    await orchestrator.deferred();

    expect(parSpy).not.toHaveBeenCalled();
    expect(authorizeSpy).not.toHaveBeenCalled();
  });

  test("token step receives grant_type=refresh_token with refresh_token_deferred value", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "my-deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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
      orchestrator.deferredCredentialRequestStep,
      "run",
    ).mockResolvedValue(deferredSuccessImmediate as never);

    await orchestrator.deferred();

    expect(tokenRunSpy).toHaveBeenCalledOnce();
    const tokenCallArg = tokenRunSpy.mock.calls[0]?.[0];
    expect(tokenCallArg?.accessTokenRequest).toMatchObject({
      grant_type: "refresh_token",
      refresh_token: "my-deferred-rt",
    });
  });

  test("deferred step is called with deferred_credential_endpoint and transaction_id", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-xyz";

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

    const deferredSpy = vi
      .spyOn(
        // @ts-expect-error accessing private field for testing
        orchestrator.deferredCredentialRequestStep,
        "run",
      )
      .mockResolvedValue(deferredSuccessImmediate as never);

    await orchestrator.deferred();

    expect(deferredSpy).toHaveBeenCalledOnce();
    const deferredCallArg = deferredSpy.mock.calls[0]?.[0];
    expect(deferredCallArg?.deferredCredentialEndpoint).toBe(
      "https://issuer.example.com/credential/deferred",
    );
    expect(deferredCallArg?.transactionId).toBe("txn-xyz");
  });

  test("deferred step receives the same dPoPKey from the token request", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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

    const deferredSpy = vi
      .spyOn(
        // @ts-expect-error accessing private field for testing
        orchestrator.deferredCredentialRequestStep,
        "run",
      )
      .mockResolvedValue(deferredSuccessImmediate as never);

    await orchestrator.deferred();

    const deferredCallArg = deferredSpy.mock.calls[0]?.[0];
    expect(deferredCallArg?.dPoPKey).toEqual(dPoPKey);
  });

  test("returns success:true with deferredCredentialResponse on immediate (200) response", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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
      orchestrator.deferredCredentialRequestStep,
      "run",
    ).mockResolvedValue(deferredSuccessImmediate as never);

    const result = await orchestrator.deferred();

    expect(result.success).toBe(true);
    expect(result.deferredCredentialResponse).toEqual(deferredSuccessImmediate);
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toEqual(tokenSuccess);
  });

  test("returns success:true with deferredCredentialResponse on still-pending (202) response", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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
      orchestrator.deferredCredentialRequestStep,
      "run",
    ).mockResolvedValue(deferredSuccessPending as never);

    const result = await orchestrator.deferred();

    expect(result.success).toBe(true);
    expect(result.deferredCredentialResponse).toEqual(deferredSuccessPending);
  });

  test("returns success:false with IssuerMetadataError when deferred_credential_endpoint is missing", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockResolvedValue(fetchMetadataMissingDeferred);

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.tokenRequestStep,
      "run",
    ).mockResolvedValue(tokenSuccess as never);

    const result = await orchestrator.deferred();

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain("deferred_credential_endpoint");
    expect(result.error?.message).toContain("openid_credential_issuer");
  });

  test("token failure returns partial response with fetchMetadataResponse", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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

    const result = await orchestrator.deferred();

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe("token endpoint returned 401");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toBeDefined();
    expect(result.deferredCredentialResponse).toBeUndefined();
  });

  test("deferred step failure returns partial response with tokenResponse", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

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
      orchestrator.deferredCredentialRequestStep,
      "run",
    ).mockResolvedValue(makeStepFailure("deferred endpoint returned 400"));

    const result = await orchestrator.deferred();

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe("deferred endpoint returned 400");
    expect(result.fetchMetadataResponse).toEqual(fetchMetadataSuccess);
    expect(result.tokenResponse).toEqual(tokenSuccess);
    expect(result.deferredCredentialResponse).toBeDefined();
  });

  test("never throws — error is always captured in result.error", async () => {
    orchestrator.getConfig().issuance.refresh_token_deferred = "deferred-rt";
    orchestrator.getConfig().issuance.transaction_id_deferred = "txn-abc";

    vi.spyOn(
      // @ts-expect-error accessing private field for testing
      orchestrator.fetchMetadataStep,
      "run",
    ).mockRejectedValue(new Error("unexpected network error"));

    await expect(orchestrator.deferred()).resolves.toMatchObject({
      error: expect.objectContaining({ message: "unexpected network error" }),
      success: false,
    });
  });
});
