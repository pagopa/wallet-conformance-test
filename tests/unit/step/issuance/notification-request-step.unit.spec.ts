/**
 * Unit tests for NotificationRequestDefaultStep.
 *
 * Verifies that:
 * - The step builds the correct JSON body with notification_id and event.
 * - The step sets Authorization: DPoP <accessToken>, DPoP, and Content-Type headers.
 * - HTTP 204 is treated as success with response.status === 204.
 * - Any status other than 204 causes a failure (success: false).
 * - Errors are always captured in result.error — the step never throws.
 */

import { createTokenDPoP } from "@pagopa/io-wallet-oauth2";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Config } from "@/types";

import { createQuietLogger } from "@/logic/logs";
import { NotificationRequestDefaultStep } from "@/step/issuance/notification-request-step";

// ---------------------------------------------------------------------------
// Module-level mocks
// ---------------------------------------------------------------------------

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createTokenDPoP: vi.fn(),
  };
});

const mockFetch = vi.fn();

vi.mock("@/logic", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/logic")>();
  return {
    ...actual,
    fetchWithConfig: vi.fn(() => mockFetch),
    partialCallbacks: actual.partialCallbacks,
    signJwtCallback: vi.fn(() => vi.fn()),
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const makeConfig = (): Config =>
  ({
    logging: {
      log_file: "",
      log_file_format: "json",
      log_format: "pretty",
      log_level: "silent",
    },
    network: { max_retries: 1, timeout: 10, user_agent: "test" },
    steps_mapping: { mapping: {} },
    trust: { trust_anchor_entity_configuration_url: "" },
    trust_anchor: { port: 3000, ta_url: "http://localhost:3000" },
    wallet: {
      backup_storage_path: "./backup",
      credentials_storage_path: "./credentials",
      wallet_version: "1.0",
    },
  }) as unknown as Config;

const mockDpopKey = {
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

const defaultOptions = {
  accessToken: "mock-access-token",
  dPoPKey: mockDpopKey,
  event: "credential_deleted" as const,
  notificationEndpoint: "https://issuer.example.com/notification",
  notificationId: "mock-notification-id",
};

function makeStep() {
  return new NotificationRequestDefaultStep(makeConfig(), createQuietLogger());
}

function setupHappyPathMocks(status = 204) {
  vi.mocked(createTokenDPoP).mockResolvedValue({
    jwt: "mock-dpop-jwt",
  } as never);

  mockFetch.mockResolvedValue({ status });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("NotificationRequestDefaultStep", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("JSON body construction", () => {
    it("sends notification_id and event in the request body", async () => {
      setupHappyPathMocks();
      const step = makeStep();

      await step.run(defaultOptions);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [, init] = mockFetch.mock.calls[0] as [
        string,
        RequestInit & { body: string },
      ];
      const body = JSON.parse(init.body) as Record<string, unknown>;

      expect(body.notification_id).toBe("mock-notification-id");
      expect(body.event).toBe("credential_deleted");
    });
  });

  describe("HTTP headers", () => {
    it("sets Authorization: DPoP <accessToken>", async () => {
      setupHappyPathMocks();
      const step = makeStep();

      await step.run(defaultOptions);

      const [, init] = mockFetch.mock.calls[0] as [
        string,
        RequestInit & { headers: Record<string, string> },
      ];
      expect(init.headers.Authorization).toBe("DPoP mock-access-token");
    });

    it("sets DPoP header with the generated proof", async () => {
      setupHappyPathMocks();
      const step = makeStep();

      await step.run(defaultOptions);

      const [, init] = mockFetch.mock.calls[0] as [
        string,
        RequestInit & { headers: Record<string, string> },
      ];
      expect(init.headers.DPoP).toBe("mock-dpop-jwt");
    });

    it("sets Content-Type: application/json", async () => {
      setupHappyPathMocks();
      const step = makeStep();

      await step.run(defaultOptions);

      const [, init] = mockFetch.mock.calls[0] as [
        string,
        RequestInit & { headers: Record<string, string> },
      ];
      expect(init.headers["Content-Type"]).toBe("application/json");
    });

    it("issues a POST request to the notification endpoint", async () => {
      setupHappyPathMocks();
      const step = makeStep();

      await step.run(defaultOptions);

      const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
      expect(url).toBe("https://issuer.example.com/notification");
      expect(init.method).toBe("POST");
    });
  });

  describe("DPoP proof", () => {
    it("builds DPoP with htm: POST and htu: notificationEndpoint", async () => {
      setupHappyPathMocks();
      const step = makeStep();

      await step.run(defaultOptions);

      expect(createTokenDPoP).toHaveBeenCalledOnce();
      const dpopCallArg = vi.mocked(createTokenDPoP).mock.calls[0]?.[0];
      expect(dpopCallArg?.tokenRequest).toMatchObject({
        method: "POST",
        url: "https://issuer.example.com/notification",
      });
    });
  });

  describe("success path (HTTP 204)", () => {
    it("returns success: true with status 204", async () => {
      setupHappyPathMocks(204);
      const step = makeStep();

      const result = await step.run(defaultOptions);

      expect(result.success).toBe(true);
      expect(result.response?.status).toBe(204);
    });
  });

  describe("failure paths", () => {
    it("returns success: false when status is 200 (not 204)", async () => {
      setupHappyPathMocks(200);
      const step = makeStep();

      const result = await step.run(defaultOptions);

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain("200");
    });

    it("returns success: false when status is 400", async () => {
      setupHappyPathMocks(400);
      const step = makeStep();

      const result = await step.run(defaultOptions);

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain("400");
    });

    it("never throws — fetch failure is captured in result.error", async () => {
      vi.mocked(createTokenDPoP).mockResolvedValue({ jwt: "mock" } as never);
      mockFetch.mockRejectedValue(new Error("network error"));

      const step = makeStep();

      await expect(step.run(defaultOptions)).resolves.toMatchObject({
        error: expect.objectContaining({ message: "network error" }),
        success: false,
      });
    });
  });
});
