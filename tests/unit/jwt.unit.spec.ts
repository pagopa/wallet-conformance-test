import type { JsonWebKey } from "@pagopa/io-wallet-oid-federation";

import { describe, expect, it } from "vitest";

import { signCallback } from "@/logic/jwt";

/**
 * Unit tests for signCallback in src/logic/jwt.ts.
 *
 * These tests verify:
 *   - the return value is a Uint8Array
 *   - the raw bytes form a valid ECDSA signature verifiable with the
 *     matching public key
 *   - the hash algorithm is correctly derived from the JWA alg name
 *     (ES256→SHA-256, ES384→SHA-384, ES512→SHA-512)
 *   - when alg is absent the function defaults to ES256/SHA-256
 */

/**
 * Generate an extractable ECDSA key pair using Web Crypto and export both
 * halves as plain JWK objects. Using crypto.subtle directly (rather than
 * jose's generateKeyPair) so the keys are extractable.
 */
async function generateExtractableEcKeyPair(namedCurve: string): Promise<{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- crypto.subtle.exportKey returns DOM JsonWebKey; any is needed to spread extra fields
  privateJwk: any;
  publicKey: CryptoKey;
}> {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve },
    true /* extractable */,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", privateKey);
  return { privateJwk, publicKey };
}

describe("signCallback", () => {
  it.each([
    { alg: "ES256", hashAlgorithm: "SHA-256" as const, namedCurve: "P-256" },
    { alg: "ES384", hashAlgorithm: "SHA-384" as const, namedCurve: "P-384" },
    { alg: "ES512", hashAlgorithm: "SHA-512" as const, namedCurve: "P-521" },
  ])(
    "$alg: returns a Uint8Array that verifies against the public key",
    async ({ alg, hashAlgorithm, namedCurve }) => {
      const { privateJwk, publicKey } =
        await generateExtractableEcKeyPair(namedCurve);

      const jwk = {
        ...privateJwk,
        alg,
        kid: "test-key",
      } as unknown as JsonWebKey;

      const toBeSigned = new TextEncoder().encode("header.payload");

      const signature = await signCallback({ jwk, toBeSigned });

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);

      const isValid = await crypto.subtle.verify(
        { hash: hashAlgorithm, name: "ECDSA" },
        publicKey,
        Buffer.from(signature),
        toBeSigned,
      );

      expect(
        isValid,
        `signature should be valid for ${alg} with ${hashAlgorithm}`,
      ).toBe(true);
    },
  );

  it("defaults to ES256/SHA-256 when alg is absent from the JWK", async () => {
    const { privateJwk, publicKey } =
      await generateExtractableEcKeyPair("P-256");

    // Intentionally omit alg to exercise the ?? "ES256" branch
    const jwk = { ...privateJwk, kid: "test-key" } as unknown as JsonWebKey;

    const toBeSigned = new TextEncoder().encode("header.payload");

    const signature = await signCallback({ jwk, toBeSigned });

    expect(signature).toBeInstanceOf(Uint8Array);

    const isValid = await crypto.subtle.verify(
      { hash: "SHA-256", name: "ECDSA" },
      publicKey,
      Buffer.from(signature),
      toBeSigned,
    );

    expect(
      isValid,
      "signature should verify with SHA-256 when alg is absent",
    ).toBe(true);
  });
});
