import {
  createTokenDPoP,
  Jwk,
  JwtSignerJwk,
  SignJwtCallback,
} from "@pagopa/io-wallet-oauth2";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import KSUID from "ksuid";

import { partialCallbacks, signJwtCallback } from "@/logic";
import {
  CredentialRequestDefaultStep,
  CredentialRequestResponse,
  CredentialRequestStepOptions,
} from "@/step/issuance/credential-request-step";
import { KeyPairJwk } from "@/types";

// ---------------------------------------------------------------------------
// SignJwtCallback factories (credential proof manipulation)
// ---------------------------------------------------------------------------

/**
 * Returns a SignJwtCallback that signs with HS256 (symmetric algorithm).
 * Symmetric algorithms MUST NOT be used per IT-Wallet spec.
 * Used for CI_074.
 *
 * Re-exported from par-validation-helpers pattern for convenience.
 */
export function signWithHS256(secret: string): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const k = Buffer.from(secret).toString("base64url");
    const octJwk = { k, kty: "oct" } as Jwk; // full, valid oct JWK

    const key = await importJWK({ k, kty: "oct" }, "HS256");
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, alg: "HS256", jwk: octJwk }) // override jwk
      .sign(key);

    return {
      jwt,
      signerJwk: octJwk, // matches header, includes required `k`
    };
  };
}

/**
 * Returns a SignJwtCallback that strips a required claim from the JWT payload
 * before signing. Used for CI_071 (missing required claim).
 *
 * @param claim - The payload claim name to remove (e.g. "nonce", "iat", "iss")
 * @param realPrivateKey - The key to sign with after removing the claim
 * @param realPublicKey - The public key to embed in the response
 */
export function signWithoutClaim(
  claim: string,
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importKeyPairJwk(realPrivateKey);
    const modifiedPayload = Object.fromEntries(
      Object.entries(payload as Record<string, unknown>).filter(
        ([k]) => k !== claim,
      ),
    );

    const jwt = await new SignJWT(modifiedPayload)
      .setProtectedHeader(header)
      .sign(key);

    return { jwt, signerJwk: realPublicKey as Jwk };
  };
}

/**
 * Returns a SignJwtCallback that embeds the private key `d` parameter inside
 * the `jwk` header of the JWT proof.
 *
 * The issuer MUST reject proofs whose JWK header contains private key material.
 * Used for CI_076.
 */
export function signWithPrivateKeyInHeader(
  keyPair: KeyPairJwk,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importKeyPairJwk(keyPair);
    // Build a JWK with the private `d` parameter included
    const jwkWithPrivate = { ...keyPair } as Record<string, unknown>;

    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, jwk: jwkWithPrivate })
      .sign(key);

    return { jwt, signerJwk: keyPair as Jwk };
  };
}

/**
 * Returns a SignJwtCallback that signs with a fresh, unrelated EC key pair,
 * but embeds a different public key in the `jwk` header.
 *
 * The issuer MUST reject because the signature does not verify against the
 * declared JWK in the proof header.
 * Used for CI_075.
 */
export function signWithWrongKey(): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const { privateKey: signingPrivate } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const { publicKey: differentPublic } = await generateKeyPair("ES256", {
      extractable: true,
    });

    const signingPrivateJwk = await exportJWK(signingPrivate);
    const differentPublicJwk = await exportJWK(differentPublic);

    const key = await importJWK(signingPrivateJwk, "ES256");
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader(header)
      .sign(key);

    return {
      jwt,
      signerJwk: { ...differentPublicJwk, kty: "EC" } as Jwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that overrides the `typ` header claim.
 * Used for CI_073 (wrong proof type declaration).
 *
 * @param typ - The replacement `typ` value (e.g. "JWT" instead of "openid4vci-proof+jwt")
 * @param realPrivateKey - The key to sign with
 * @param realPublicKey - The public key to embed in the response
 */
export function signWithWrongTyp(
  typ: string,
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importKeyPairJwk(realPrivateKey);
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, typ })
      .sign(key);

    return { jwt, signerJwk: realPublicKey as Jwk };
  };
}

// ---------------------------------------------------------------------------
// Step class factory helpers
// ---------------------------------------------------------------------------

/**
 * Wraps a credential request step class and injects overrides into the
 * createCredentialRequest options before each execution.
 *
 * Mirrors `withParOverrides` from par-validation-helpers.ts.
 */
export function withCredentialRequestOverrides(
  StepClass: typeof CredentialRequestDefaultStep,
  overrides: CredentialRequestStepOptions["createCredentialRequestOverrides"],
): typeof CredentialRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: CredentialRequestStepOptions,
    ): Promise<CredentialRequestResponse> {
      return super.run({
        ...options,
        createCredentialRequestOverrides: {
          ...options.createCredentialRequestOverrides,
          ...overrides,
        },
      });
    }
  } as typeof CredentialRequestDefaultStep;
}

/**
 * Wraps a credential request step class and replaces the `signJwt` callback
 * used for the credential proof JWT.
 *
 * Mirrors `withSignJwtOverride` from par-validation-helpers.ts.
 */
export function withCredentialSignJwtOverride(
  StepClass: typeof CredentialRequestDefaultStep,
  signJwt: SignJwtCallback,
): typeof CredentialRequestDefaultStep {
  return withCredentialRequestOverrides(StepClass, {
    callbacks: { signJwt },
  });
}

/**
 * Wraps a credential request step to send a DPoP proof signed by a completely
 * different key — not the unit key from the wallet attestation.
 *
 * Used for CI_083: proof key MUST equal DPoP key.
 */
export function withDPoPSignedByWrongKey(
  StepClass: typeof CredentialRequestDefaultStep,
): typeof CredentialRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: CredentialRequestStepOptions,
    ): Promise<CredentialRequestResponse> {
      const { privateKey: wrongPrivate, publicKey: wrongPublic } =
        await generateKeyPair("ES256", { extractable: true });
      const wrongPrivateJwk = await exportJWK(wrongPrivate);
      const wrongPublicJwk = await exportJWK(wrongPublic);
      const wrongKid = KSUID.randomSync().string;

      const wrongSigner: JwtSignerJwk = {
        alg: "ES256",
        method: "jwk",
        publicJwk: { ...wrongPublicJwk, kid: wrongKid, kty: "EC" } as Jwk,
      };

      const dpopOptions = {
        accessToken: options.accessToken,
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([
            { ...wrongPrivateJwk, kid: wrongKid, kty: "EC" } as KeyPairJwk,
          ]),
        },
        signer: wrongSigner,
        tokenRequest: {
          method: "POST" as const,
          url: options.credentialRequestEndpoint,
        },
      };

      const { jwt: tamperedDPoP } = await createTokenDPoP(dpopOptions);

      return super.run({ ...options, dPoPOverride: tamperedDPoP });
    }
  } as typeof CredentialRequestDefaultStep;
}

/**
 * Wraps a credential request step class to send a DPoP that has no `ath`
 * claim at all (as if the token-endpoint DPoP were reused at the credential
 * endpoint). The signature is valid.
 *
 * Used for CI_082d: issuer MUST reject because the `ath` claim is mandatory
 * at the credential endpoint per RFC 9449.
 */
export function withNoAthDPoP(
  StepClass: typeof CredentialRequestDefaultStep,
): typeof CredentialRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: CredentialRequestStepOptions,
    ): Promise<CredentialRequestResponse> {
      const { unitKey } = options.walletAttestation;
      const { jwt: dpop } = await createTokenDPoP({
        // accessToken intentionally omitted → no ath claim in DPoP
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        signer: {
          alg: "ES256",
          method: "jwk" as const,
          publicJwk: unitKey.publicKey,
        },
        tokenRequest: {
          method: "POST" as const,
          url: options.credentialRequestEndpoint,
        },
      });
      return super.run({ ...options, dPoPOverride: dpop });
    }
  } as typeof CredentialRequestDefaultStep;
}

/**
 * Wraps a credential request step class to bypass DPoP entirely.
 * Sends an empty string as the DPoP proof, which the issuer cannot validate.
 *
 * Used for CI_082a.
 */
export function withNoDPoP(
  StepClass: typeof CredentialRequestDefaultStep,
): typeof CredentialRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: CredentialRequestStepOptions,
    ): Promise<CredentialRequestResponse> {
      return super.run({ ...options, dPoPOverride: "" });
    }
  } as typeof CredentialRequestDefaultStep;
}

/**
 * Wraps a credential request step class to send a DPoP whose `ath` claim
 * contains the SHA-256 hash of a fake access token, not the real one.
 * The signature is valid; only the `ath` value is wrong.
 *
 * Used for CI_082c: issuer MUST reject because ath ≠ SHA-256(real access token).
 */
export function withWrongAthDPoP(
  StepClass: typeof CredentialRequestDefaultStep,
): typeof CredentialRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: CredentialRequestStepOptions,
    ): Promise<CredentialRequestResponse> {
      const { unitKey } = options.walletAttestation;
      const WRONG_TOKEN = "fake-access-token-for-wrong-ath-aabbccddeeff";
      const { jwt: dpop } = await createTokenDPoP({
        accessToken: WRONG_TOKEN, // ath = SHA-256(WRONG_TOKEN), not the real token hash
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        signer: {
          alg: "ES256",
          method: "jwk" as const,
          publicJwk: unitKey.publicKey,
        },
        tokenRequest: {
          method: "POST" as const,
          url: options.credentialRequestEndpoint,
        },
      });
      return super.run({ ...options, dPoPOverride: dpop });
    }
  } as typeof CredentialRequestDefaultStep;
}

/**
 * Wraps a credential request step class to send a DPoP with `htm = "GET"`
 * (wrong HTTP method) while keeping a valid cryptographic signature.
 *
 * Used for CI_082b: issuer MUST reject because htm ≠ POST.
 */
export function withWrongHtmDPoP(
  StepClass: typeof CredentialRequestDefaultStep,
): typeof CredentialRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: CredentialRequestStepOptions,
    ): Promise<CredentialRequestResponse> {
      const { unitKey } = options.walletAttestation;
      const { jwt: dpop } = await createTokenDPoP({
        accessToken: options.accessToken,
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        signer: {
          alg: "ES256",
          method: "jwk" as const,
          publicJwk: unitKey.publicKey,
        },
        tokenRequest: {
          method: "GET" as const, // wrong method → htm = "GET"
          url: options.credentialRequestEndpoint,
        },
      });
      return super.run({ ...options, dPoPOverride: dpop });
    }
  } as typeof CredentialRequestDefaultStep;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Helper to import a KeyPairJwk for signing.
 */
async function importKeyPairJwk(
  key: KeyPairJwk,
): Promise<Awaited<ReturnType<typeof importJWK>>> {
  return importJWK(key as Parameters<typeof importJWK>[0], key.alg ?? "ES256");
}
