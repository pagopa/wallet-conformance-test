import { findRpEncryptionKey } from "#/helpers/rp-presentation";
import { describe, expect, it } from "vitest";

import type { AuthorizationRequestExecuteStepResponse } from "@/step/presentation/authorization-request-step";

const buildJwk = (kid: string, x: string) => ({
  crv: "P-256",
  kid,
  kty: "EC",
  use: "enc",
  x,
  y: "y-coordinate",
});

const buildResponse = (keys: unknown[]) =>
  ({
    requestObject: { client_metadata: { jwks: { keys } } },
  }) as unknown as AuthorizationRequestExecuteStepResponse;

const EMPTY_LISTS_ERROR =
  "RP JWKS is missing or empty in both verifier metadata and request object client_metadata";

describe("findRpEncryptionKey", () => {
  it("returns the federation key when the kid is in the federation JWKS (federation wins over client_metadata)", () => {
    const federationKey = buildJwk("fed-kid", "x-federation");
    const clientMetadataKey = buildJwk("fed-kid", "x-client-metadata");

    const result = findRpEncryptionKey(
      "fed-kid",
      [federationKey],
      buildResponse([clientMetadataKey]),
    );

    expect(result.key).toBe(federationKey);
    expect(result.source).toBe("RP JWKS (federation metadata)");
  });

  it("returns the ephemeral key when the kid is only in client_metadata.jwks", () => {
    const federationKey = buildJwk("fed-kid", "x-federation");
    const ephemeralKey = buildJwk("eph-kid", "x-ephemeral");

    const result = findRpEncryptionKey(
      "eph-kid",
      [federationKey],
      buildResponse([ephemeralKey]),
    );

    expect(result.key).toBe(ephemeralKey);
    expect(result.source).toBe(
      "client_metadata JWKS (request object, ephemeral key)",
    );
  });

  it("returns key undefined when the kid is in neither list", () => {
    const result = findRpEncryptionKey(
      "unknown-kid",
      [buildJwk("fed-kid", "x-federation")],
      buildResponse([buildJwk("eph-kid", "x-ephemeral")]),
    );

    expect(result.key).toBeUndefined();
  });

  it("throws when both lists are empty or missing", () => {
    const noClientMetadata = {
      requestObject: {},
    } as unknown as AuthorizationRequestExecuteStepResponse;

    expect(() => findRpEncryptionKey("kid", [], buildResponse([]))).toThrow(
      EMPTY_LISTS_ERROR,
    );
    expect(() =>
      findRpEncryptionKey("kid", undefined, buildResponse([])),
    ).toThrow(EMPTY_LISTS_ERROR);
    expect(() => findRpEncryptionKey("kid", [], undefined)).toThrow(
      EMPTY_LISTS_ERROR,
    );
    expect(() => findRpEncryptionKey("kid", [], noClientMetadata)).toThrow(
      EMPTY_LISTS_ERROR,
    );
  });
});
