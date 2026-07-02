/**
 * Unit tests for DeferredCredentialRequestDefaultStep.fetchDeferred()
 *
 * Verifies that:
 *  1. HTTP 202 with a mismatched transaction_id produces a descriptive error (spec violation).
 *  2. HTTP 202 with the correct transaction_id succeeds.
 *  3. HTTP 200 with credentials succeeds without any transaction_id check.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Config } from "@/types";

import { createQuietLogger } from "@/logic/logs";
import { DeferredCredentialRequestDefaultStep } from "@/step/issuance/deferred-credential-request-step";

// ---------------------------------------------------------------------------
// Module-level mocks
// ---------------------------------------------------------------------------

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createTokenDPoP: vi.fn().mockResolvedValue({ jwt: "mock-dpop-jwt" }),
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const makeConfig = (walletVersion = "V1_3"): Config =>
  ({
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
      wallet_version: walletVersion,
    },
  }) as unknown as Config;

const dPoPKey = {
  privateKey: {
    crv: "P-256",
    d: "mock-d",
    kid: "mock-kid",
    kty: "EC" as const,
  },
  publicKey: {
    crv: "P-256",
    kid: "mock-kid",
    kty: "EC" as const,
    x: "mock-x",
    y: "mock-y",
  },
};

const baseOptions = {
  accessToken: "mock-access-token",
  deferredCredentialEndpoint: "https://issuer.example.com/credential/deferred",
  dPoPKey,
  transactionId: "original-txn-id",
};

function makeStep(walletVersion = "V1_3") {
  return new DeferredCredentialRequestDefaultStep(
    makeConfig(walletVersion),
    createQuietLogger(),
  );
}

/** Stubs global.fetch to return a fake HTTP response with the given status and JSON body. */
function stubFetch(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      json: vi.fn().mockResolvedValue(body),
      ok: status >= 200 && status < 300,
      status,
    }),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DeferredCredentialRequestDefaultStep", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns success:false when 202 response has a different transaction_id", async () => {
    stubFetch(202, { interval: 5, transaction_id: "different-txn-id" });

    const step = makeStep();
    const result = await step.run(baseOptions);

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain("different-txn-id");
    expect(result.error?.message).toContain("original-txn-id");
    expect(result.error?.message).toContain("spec violation");
  });

  it("returns success:true when 202 response transaction_id matches the sent one", async () => {
    stubFetch(202, { interval: 5, transaction_id: "original-txn-id" });

    const step = makeStep();
    const result = await step.run(baseOptions);

    expect(result.success).toBe(true);
    expect(result.response).toMatchObject({
      transaction_id: "original-txn-id",
    });
  });

  it("returns success:true on 200 with credentials (no transaction_id check)", async () => {
    stubFetch(200, {
      credentials: [{ credential: "mock-credential" }],
      notification_id: "notif-abc",
    });

    const step = makeStep("V1_0");
    const result = await step.run(baseOptions);

    expect(result.success).toBe(true);
    expect(result.response).toMatchObject({
      credentials: [{ credential: "mock-credential" }],
    });
  });
});
