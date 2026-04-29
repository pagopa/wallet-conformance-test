/* eslint-disable max-lines-per-function */
/**
 * Unit tests for AuthorizationRequestDefaultStep.
 *
 * Focuses on:
 *  1. enc algorithm selection — the step must forward the correct enc value
 *     to createAuthorizationResponse via rpJwks / authorization_encrypted_response_enc
 *  2. Guard clauses — missing enc key, missing response_uri, missing dcql_query
 *  3. Step contract — failures are always returned as { success: false }, never thrown
 *
 */

import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  createAuthorizationResponse,
  fetchAuthorizationRequest,
  parseAuthorizeRequest,
} from "@pagopa/io-wallet-oid4vp";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Config } from "@/types";

import { createQuietLogger } from "@/logic/logs";
import { buildVpToken } from "@/logic/vpToken";
import { AuthorizationRequestDefaultStep } from "@/step/presentation/authorization-request-step";

// ---------------------------------------------------------------------------
// Module-level mocks — hoisted before imports by Vitest
// ---------------------------------------------------------------------------

vi.mock("@pagopa/io-wallet-oid4vp", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oid4vp")>();
  return {
    ...actual,
    createAuthorizationResponse: vi.fn(),
    fetchAuthorizationRequest: vi.fn(),
    parseAuthorizeRequest: vi.fn(),
  };
});

vi.mock("@/logic/vpToken", () => ({
  buildVpToken: vi.fn(),
}));

vi.mock("@/logic/jwt", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/logic/jwt")>();
  return {
    ...actual,
    getEncryptJweCallback: vi.fn().mockReturnValue(vi.fn()),
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal Config that satisfies StepFlow constructor requirements. */
const makeConfig = (): Config =>
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
      wallet_version: "1.0",
    },
  }) as unknown as Config;

/** Encryption JWK stub used as the `enc` key inside verifier JWKS. */
const encKey = {
  crv: "P-256",
  kid: "enc-key-1",
  kty: "EC",
  use: "enc",
  x: "mock-x",
  y: "mock-y",
};

/** Signing JWK stub (use === "sig") that must NOT be selected as enc key. */
const sigKey = {
  crv: "P-256",
  kid: "sig-key-1",
  kty: "EC",
  use: "sig",
  x: "mock-sx",
  y: "mock-sy",
};

/**
 * Common fields for verifier metadata fixtures.
 *
 * Cast as unknown because the v1.0 type exported by the federation package
 * requires scalar enc/alg fields that are irrelevant to most test cases.
 * Individual test fixtures spread over this base and add only what they need.
 */
const baseVerifierMetadata = {
  application_type: "web" as const,
  client_id: "https://verifier.example.com",
  client_name: "Test Verifier",
  jwks: { keys: [sigKey, encKey] },
  logo_uri: "https://verifier.example.com/logo.png",
  request_uris: ["https://verifier.example.com/request"],
  response_uris: ["https://verifier.example.com/response"],
  vp_formats_supported: {},
} as unknown as ItWalletCredentialVerifierMetadata;

/** Stub request object returned by parseAuthorizeRequest. */
const stubRequestObject = {
  client_id: "https://verifier.example.com",
  dcql_query: { credentials: [] },
  nonce: "test-nonce",
  response_uri: "https://verifier.example.com/response",
  state: "test-state",
};

/** Stub QR code returned by fetchAuthorizationRequest. */
const stubParsedQrCode = {
  clientId: "https://verifier.example.com",
  requestUri: "https://verifier.example.com/request",
};

/** Stub authorization response returned by createAuthorizationResponse. */
const stubAuthorizationResponse = {
  authorizationResponsePayload: {},
  jarm: { header: {}, payload: {} },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeStep() {
  return new AuthorizationRequestDefaultStep(makeConfig(), createQuietLogger());
}

function setupHappyPathMocks() {
  vi.mocked(fetchAuthorizationRequest).mockResolvedValue({
    parsedQrCode: stubParsedQrCode,
    requestObjectJwt: "header.payload.sig",
  } as never);

  vi.mocked(parseAuthorizeRequest).mockResolvedValue({
    header: { alg: "ES256", kid: "sig-key-1", typ: "JWT" },
    payload: stubRequestObject,
  } as never);

  vi.mocked(buildVpToken).mockResolvedValue({} as never);

  vi.mocked(createAuthorizationResponse).mockResolvedValue(
    stubAuthorizationResponse as never,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AuthorizationRequestDefaultStep", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // enc selection — the main fix
  // -------------------------------------------------------------------------

  describe("enc algorithm selection", () => {
    it("passes encrypted_response_enc_values_supported array to rpJwks when only the array is present in verifier metadata", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      expect(createAuthorizationResponse).toHaveBeenCalledOnce();
      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];

      // The array must be forwarded to rpJwks so the SDK can pick the first value
      expect(callArgs.rpJwks.encrypted_response_enc_values_supported).toEqual([
        "A256GCM",
      ]);
      // The scalar must be undefined so the SDK applies its own selection logic
      expect(callArgs.authorization_encrypted_response_enc).toBeUndefined();
    });

    it("passes authorization_encrypted_response_enc scalar directly when present in verifier metadata", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        // old schema — scalar field
        authorization_encrypted_response_enc: "A128CBC-HS256",
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];

      expect(callArgs.authorization_encrypted_response_enc).toBe(
        "A128CBC-HS256",
      );
    });

    it("passes undefined for authorization_encrypted_response_enc when no enc fields are set, letting the SDK use its default", async () => {
      setupHappyPathMocks();

      // Neither scalar nor array present
      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: [],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];

      expect(callArgs.authorization_encrypted_response_enc).toBeUndefined();
    });

    it("passes multiple enc values from the supported array to rpJwks intact", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM", "A128CBC-HS256"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];

      expect(callArgs.rpJwks.encrypted_response_enc_values_supported).toEqual([
        "A256GCM",
        "A128CBC-HS256",
      ]);
    });
  });

  // -------------------------------------------------------------------------
  // alg selection
  // -------------------------------------------------------------------------

  describe("alg algorithm selection", () => {
    it("passes authorization_encrypted_response_alg scalar when present in verifier metadata", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        authorization_encrypted_response_alg: "ECDH-ES+A256KW",
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];
      expect(callArgs.authorization_encrypted_response_alg).toBe(
        "ECDH-ES+A256KW",
      );
    });

    it("passes undefined for authorization_encrypted_response_alg when not set, letting the SDK use its default", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];
      expect(callArgs.authorization_encrypted_response_alg).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Guard clauses
  // -------------------------------------------------------------------------

  describe("guard clauses", () => {
    it("returns success: false when no enc key is found in verifier jwks", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        // Only a signing key — no enc key
        encrypted_response_enc_values_supported: ["A256GCM"],
        jwks: { keys: [sigKey] },
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      const result = await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain(
        "no encryption key found in verifier metadata",
      );
      expect(createAuthorizationResponse).not.toHaveBeenCalled();
    });

    it("returns success: false when response_uri is missing from the request object", async () => {
      setupHappyPathMocks();

      vi.mocked(parseAuthorizeRequest).mockResolvedValue({
        header: {},
        payload: { ...stubRequestObject, response_uri: undefined },
      } as never);

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      const result = await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain("response_uri is missing");
    });

    it("returns success: false when dcql_query is missing from the request object", async () => {
      setupHappyPathMocks();

      vi.mocked(parseAuthorizeRequest).mockResolvedValue({
        header: {},
        payload: { ...stubRequestObject, dcql_query: undefined },
      } as never);

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      const result = await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      expect(result.success).toBe(false);
      expect(result.error?.message).toContain("dcql_query is missing");
    });
  });

  // -------------------------------------------------------------------------
  // Step contract
  // -------------------------------------------------------------------------

  describe("step contract", () => {
    it("never throws — fetchAuthorizationRequest failure is captured in result.error", async () => {
      vi.mocked(fetchAuthorizationRequest).mockRejectedValue(
        new Error("network error"),
      );

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();

      await expect(
        step.run({
          credentials: [],
          verifierMetadata,
          walletAttestation: {} as never,
        }),
      ).resolves.toMatchObject({
        error: expect.objectContaining({ message: "network error" }),
        success: false,
      });
    });

    it("returns success: true and the full response on the happy path", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      const result = await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      expect(result.success).toBe(true);
      expect(result.response).toMatchObject({
        authorizationResponse: stubAuthorizationResponse,
        parsedQrCode: stubParsedQrCode,
        requestObject: stubRequestObject,
        responseUri: stubRequestObject.response_uri,
      });
    });

    it("forwards the correct jwks from verifier metadata to rpJwks", async () => {
      setupHappyPathMocks();

      const verifierMetadata = {
        ...baseVerifierMetadata,
        encrypted_response_enc_values_supported: ["A256GCM"],
      } as unknown as ItWalletCredentialVerifierMetadata;

      const step = makeStep();
      await step.run({
        credentials: [],
        verifierMetadata,
        walletAttestation: {} as never,
      });

      const callArgs = vi.mocked(createAuthorizationResponse).mock.calls[0]![0];
      expect(callArgs.rpJwks.jwks).toEqual(
        (baseVerifierMetadata as unknown as { jwks: unknown }).jwks,
      );
    });
  });
});
