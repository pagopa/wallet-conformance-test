/**
 * Unit tests for PushedAuthorizationRequestDefaultStep — PID authorization
 * details (B1-6.2 hook, B1-6.3 concatenation, B1-6.5 withPidPar override).
 *
 * Focuses on the shape of `authorization_details` forwarded to the SDK's
 * `createPushedAuthorizationRequest`, across `[issuance_pid].mode` values:
 *
 *   1. mode = none / absent → no PID detail (standard (Q)EAA flow unchanged)
 *   2. mode = l3 / l2plus   → exactly one PID detail, never duplicated
 *   3. mixed credential ids → PID appended once alongside non-PID details
 *   4. withPidPar(...)       → hook overridden independently of config mode
 */

import { withPidPar } from "#/helpers/par-validation-helpers";
import {
  createPushedAuthorizationRequest,
  fetchPushedAuthorizationResponse,
} from "@pagopa/io-wallet-oauth2";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Config } from "@/types";

import { createQuietLogger } from "@/logic/logs";
import {
  AuthorizationDetail,
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestStepOptions,
} from "@/step/issuance/pushed-authorization-request-step";
import { PID_CREDENTIAL_CONFIGURATION_ID } from "@/types/pid-issuance";

// ---------------------------------------------------------------------------
// Module-level mocks — hoisted before imports by Vitest
// ---------------------------------------------------------------------------

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createPushedAuthorizationRequest: vi.fn(),
    fetchPushedAuthorizationResponse: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type PidMode = "l2plus" | "l3" | "none";

/** Minimal Config that satisfies the StepFlow constructor and the PAR step. */
const makeConfig = (
  mode?: PidMode,
  issuancePidExtra?: Record<string, unknown>,
): Config =>
  ({
    issuance_pid: mode ? { mode, ...issuancePidExtra } : undefined,
    logging: {
      log_file: "",
      log_file_format: "json",
      log_format: "pretty",
      log_level: "silent",
    },
    network: { max_retries: 1, timeout: 10, user_agent: "test" },
    wallet: {
      backup_storage_path: "./backup",
      credentials_storage_path: "./credentials",
      wallet_version: "1.0",
    },
  }) as unknown as Config;

/** Fake unit key — only `publicKey.kid` and `privateKey` are read by the step. */
const fakeKey = {
  privateKey: {
    crv: "P-256",
    d: "d",
    kid: "client-kid",
    kty: "EC",
    x: "x",
    y: "y",
  },
  publicKey: { crv: "P-256", kid: "client-kid", kty: "EC", x: "x", y: "y" },
};

const DRIVING_LICENSE_ID = "dc_sd_jwt_DrivingLicense";

const makeOptions = (
  credentialConfigurationIds: string[],
): PushedAuthorizationRequestStepOptions =>
  ({
    baseUrl: "https://issuer.example.com",
    clientId: "client-kid",
    credentialConfigurationIds,
    popAttestation: "pop.jwt",
    pushedAuthorizationRequestEndpoint: "https://issuer.example.com/par",
    walletAttestation: {
      attestation: "fake.attestation.jwt",
      providerKey: fakeKey,
      unitKey: fakeKey,
    },
  }) as unknown as PushedAuthorizationRequestStepOptions;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract the `authorization_details` forwarded to the SDK builder. */
function capturedAuthorizationDetails(): AuthorizationDetail[] {
  const [firstCall] = vi.mocked(createPushedAuthorizationRequest).mock.calls;
  if (!firstCall) {
    throw new Error("createPushedAuthorizationRequest was not called");
  }
  return (
    (firstCall[0] as { authorization_details?: AuthorizationDetail[] })
      .authorization_details ?? []
  );
}

/** All `credential_configuration_id` values present in `authorization_details`. */
function credentialIds(details: AuthorizationDetail[]): (string | undefined)[] {
  return details.map((detail) =>
    "credential_configuration_id" in detail
      ? detail.credential_configuration_id
      : undefined,
  );
}

async function runStep(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  config: Config,
  options: PushedAuthorizationRequestStepOptions,
) {
  const step = new StepClass(config, createQuietLogger());
  return step.run(options);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("PushedAuthorizationRequestDefaultStep — PID authorization_details", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createPushedAuthorizationRequest).mockResolvedValue({
      pkceCodeVerifier: "verifier-123",
    } as never);
    vi.mocked(fetchPushedAuthorizationResponse).mockResolvedValue({
      expires_in: 60,
      request_uri: "urn:ietf:params:oauth:request_uri:abc",
    } as never);
  });

  it("mode = none: no PID detail is added (standard flow unchanged)", async () => {
    const result = await runStep(
      PushedAuthorizationRequestDefaultStep,
      makeConfig("none"),
      makeOptions([DRIVING_LICENSE_ID]),
    );

    expect(result.error?.message).toBeUndefined();
    expect(result.success).toBe(true);
    const details = capturedAuthorizationDetails();
    expect(details).toEqual([
      {
        credential_configuration_id: DRIVING_LICENSE_ID,
        type: "openid_credential",
      },
    ]);
  });

  it("[issuance_pid] absent: behaves identically to mode = none", async () => {
    await runStep(
      PushedAuthorizationRequestDefaultStep,
      makeConfig(),
      makeOptions([DRIVING_LICENSE_ID]),
    );

    expect(credentialIds(capturedAuthorizationDetails())).toEqual([
      DRIVING_LICENSE_ID,
    ]);
  });

  it.each(["l3", "l2plus"] as const)(
    "mode = %s: a single PID detail is present and not duplicated",
    async (mode) => {
      const result = await runStep(
        PushedAuthorizationRequestDefaultStep,
        makeConfig(mode),
        makeOptions([PID_CREDENTIAL_CONFIGURATION_ID]),
      );

      expect(result.error?.message).toBeUndefined();
      expect(result.success).toBe(true);
      const details = capturedAuthorizationDetails();
      expect(details).toHaveLength(1);
      expect(details).toEqual([
        {
          credential_configuration_id: PID_CREDENTIAL_CONFIGURATION_ID,
          type: "openid_credential",
        },
      ]);
    },
  );

  it("mode = l3 with a mixed id list: PID appended once alongside others", async () => {
    await runStep(
      PushedAuthorizationRequestDefaultStep,
      makeConfig("l3"),
      makeOptions([PID_CREDENTIAL_CONFIGURATION_ID, DRIVING_LICENSE_ID]),
    );

    const ids = credentialIds(capturedAuthorizationDetails());
    expect(ids).toHaveLength(2);
    expect(ids).toContain(DRIVING_LICENSE_ID);
    expect(
      ids.filter((id) => id === PID_CREDENTIAL_CONFIGURATION_ID),
    ).toHaveLength(1);
  });

  describe("withPidPar override (B1-6.5)", () => {
    it("forces a PID detail even when mode = none", async () => {
      const Step = withPidPar(PushedAuthorizationRequestDefaultStep, [
        {
          credential_configuration_id: PID_CREDENTIAL_CONFIGURATION_ID,
          type: "openid_credential",
        },
      ]);

      await runStep(
        Step,
        makeConfig("none"),
        makeOptions([DRIVING_LICENSE_ID]),
      );

      const ids = credentialIds(capturedAuthorizationDetails());
      expect(ids).toContain(PID_CREDENTIAL_CONFIGURATION_ID);
      expect(ids).toContain(DRIVING_LICENSE_ID);
    });

    it("strips the PID detail via a derive function even when mode = l3", async () => {
      const Step = withPidPar(PushedAuthorizationRequestDefaultStep, () => []);

      await runStep(
        Step,
        makeConfig("l3"),
        makeOptions([PID_CREDENTIAL_CONFIGURATION_ID]),
      );

      expect(capturedAuthorizationDetails()).toEqual([]);
    });
  });

  describe("it_l2+document_proof (B1-6.4)", () => {
    const docProofConfig = {
      document_proof_enabled: true,
      document_proof_idphinting: "https://idp.example.org",
      document_proof_redirect_uri: "https://wallet.example.org/challenge",
    };

    it("mode = l2plus with the flag off: no document_proof detail", async () => {
      await runStep(
        PushedAuthorizationRequestDefaultStep,
        makeConfig("l2plus"),
        makeOptions([PID_CREDENTIAL_CONFIGURATION_ID]),
      );

      const types = capturedAuthorizationDetails().map((d) => d.type);
      expect(types).toEqual(["openid_credential"]);
    });

    it("mode = l2plus with the flag on: appends it_l2+document_proof", async () => {
      await runStep(
        PushedAuthorizationRequestDefaultStep,
        makeConfig("l2plus", docProofConfig),
        makeOptions([PID_CREDENTIAL_CONFIGURATION_ID]),
      );

      const details = capturedAuthorizationDetails();
      expect(details).toHaveLength(2);
      expect(details).toContainEqual({
        credential_configuration_id: PID_CREDENTIAL_CONFIGURATION_ID,
        type: "openid_credential",
      });
      expect(details).toContainEqual({
        challenge_method: "mrtd+ias",
        challenge_redirect_uri: "https://wallet.example.org/challenge",
        idphinting: "https://idp.example.org",
        type: "it_l2+document_proof",
      });
    });

    it("mode = l3 with the flag on: never adds document_proof (L3 has no MRTD)", async () => {
      await runStep(
        PushedAuthorizationRequestDefaultStep,
        makeConfig("l3", docProofConfig),
        makeOptions([PID_CREDENTIAL_CONFIGURATION_ID]),
      );

      const types = capturedAuthorizationDetails().map((d) => d.type);
      expect(types).toEqual(["openid_credential"]);
    });
  });
});
