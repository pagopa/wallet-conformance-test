import { buildTamperedPopJwt } from "#/helpers/par-validation-helpers";
import {
  createTokenDPoP,
  fetchTokenResponse,
  type FetchTokenResponseOptions,
  Jwk,
  JwtSignerJwk,
} from "@pagopa/io-wallet-oauth2";
import { UnexpectedStatusCodeError } from "@pagopa/io-wallet-utils";
import { exportJWK, generateKeyPair } from "jose";
import { randomUUID } from "node:crypto";
import { z } from "zod";

import type {
  TokenRequestExecuteResponse,
  TokenRequestResponse,
  TokenRequestStepOptions,
} from "@/step/issuance";

import {
  createKeys,
  fetchWithConfig,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { TokenRequestDefaultStep } from "@/step/issuance";
import { KeyPairJwk } from "@/types";

const wrongClientAttestationPopAudience = "https://attacker.example.com";

/**
 * Returns a copy of `token` with its last character changed.
 * Length is preserved so the tampered value targets modification-integrity
 * protection rather than length or format validation.
 */
export function tamperTokenValue(token: string): string {
  if (token.length === 0) {
    return token;
  }
  const index = token.length - 1;
  const replacement = token[index] === "A" ? "B" : "A";
  return `${token.slice(0, index)}${replacement}`;
}

export function withInvalidClientAttestationPop(
  StepClass: typeof TokenRequestDefaultStep,
): typeof TokenRequestDefaultStep {
  return class extends StepClass {
    async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
      const invalidPop = await buildTamperedPopJwt({
        authorizationServer: options.accessTokenEndpoint,
        clientAttestation: options.walletAttestation.attestation,
        config: this.ioWalletSdkConfig,
        realUnitKey: options.walletAttestation.unitKey.privateKey,
        wrongAud: wrongClientAttestationPopAudience,
      });

      return super.run({
        ...options,
        popAttestation: invalidPop,
      });
    }
  } as typeof TokenRequestDefaultStep;
}

/**
 * Wraps a token request step class to send a DPoP proof with `htm = "GET"`
 * (wrong HTTP method) while keeping a valid cryptographic signature.
 *
 * Used for CI_092: issuer MUST reject the refresh-token reissuance request
 * because the DPoP proof does not match the token endpoint method (RFC 9449 §4.3).
 */
export function withInvalidRefreshTokenDPoP(
  StepClass: typeof TokenRequestDefaultStep,
): typeof TokenRequestDefaultStep {
  return class extends StepClass {
    async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
      const { unitKey } = options.walletAttestation;
      const invalidDpop = await createTokenDPoP({
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        signer: {
          alg: "ES256",
          method: "jwk",
          publicJwk: unitKey.publicKey,
        },
        tokenRequest: {
          method: "GET", // wrong method → htm = "GET" instead of "POST"
          url: options.accessTokenEndpoint,
        },
      });

      return super.run({
        ...options,
        dpopProof: invalidDpop,
      });
    }
  } as typeof TokenRequestDefaultStep;
}

/**
 * Wraps a token request step class to send the refresh-token token request
 * without any DPoP proof header.
 *
 * Used for CI_102: the issuer MUST reject the token request because the
 * DPoP proof is entirely absent (RFC 9449 §5.2).
 */
export function withMissingRefreshTokenDPoP(
  StepClass: typeof TokenRequestDefaultStep,
): typeof TokenRequestDefaultStep {
  return class extends StepClass {
    async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
      return this.execute<TokenRequestExecuteResponse>(async () => {
        // Generate a throwaway key pair so the return type is satisfied if the
        // server unexpectedly accepts the request (which would be a compliance
        // failure — the test asserts success: false).
        const dPoPKey = await createKeys();

        const fetchOptions = {
          accessTokenEndpoint: options.accessTokenEndpoint,
          accessTokenRequest: options.accessTokenRequest,
          callbacks: { fetch: fetchWithConfig(this.config.network) },
          clientAttestationDPoP: options.popAttestation,
          walletAttestation: options.walletAttestation.attestation,
        } satisfies Omit<FetchTokenResponseOptions, "dPoP">;

        // dPoP intentionally omitted — tests that the issuer rejects requests
        // without a DPoP proof (RFC 9449 §5.2).
        const tokenResponse = await fetchTokenResponse(
          fetchOptions as FetchTokenResponseOptions,
        );

        return { ...tokenResponse, dPoPKey };
      });
    }
  } as typeof TokenRequestDefaultStep;
}

/**
 * Wraps a token request step class to send a valid DPoP proof for the token
 * endpoint, but signed with a fresh key that is unrelated to the key bound to
 * the Refresh Token.
 *
 * Used for CI_093: the issuer MUST reject the refresh-token reissuance request
 * because the DPoP proof key thumbprint does not match the Refresh Token
 * confirmation binding.
 */
export function withRefreshTokenDPoPSignedByWrongKey(
  StepClass: typeof TokenRequestDefaultStep,
): typeof TokenRequestDefaultStep {
  return class extends StepClass {
    async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
      const { privateKey: wrongPrivate, publicKey: wrongPublic } =
        await generateKeyPair("ES256", { extractable: true });
      const wrongPrivateJwk = await exportJWK(wrongPrivate);
      const wrongPublicJwk = await exportJWK(wrongPublic);
      const wrongKid = randomUUID();

      const wrongSigner: JwtSignerJwk = {
        alg: "ES256",
        method: "jwk",
        publicJwk: { ...wrongPublicJwk, kid: wrongKid, kty: "EC" } as Jwk,
      };

      const wrongKeyDpop = await createTokenDPoP({
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([
            { ...wrongPrivateJwk, kid: wrongKid, kty: "EC" } as KeyPairJwk,
          ]),
        },
        signer: wrongSigner,
        tokenRequest: {
          method: "POST" as const,
          url: options.accessTokenEndpoint,
        },
      });

      return super.run({
        ...options,
        dpopProof: wrongKeyDpop,
      });
    }
  } as typeof TokenRequestDefaultStep;
}

const oauthErrorBodySchema = z.object({ error: z.string() }).passthrough();

/**
 * Extracts the OAuth `error` field from a failed token request response.
 *
 * When the token endpoint returns a non-200 status, `fetchTokenResponse` throws
 * an `UnexpectedStatusCodeError` whose `reason` property contains the raw
 * response body (JSON string).  This helper narrows the error type, parses the
 * body, and returns the `error` member so tests can assert on it without using
 * `any`.
 *
 * Returns `undefined` when:
 * - the response is undefined or succeeded
 * - the error is not an `UnexpectedStatusCodeError`
 * - the body cannot be parsed as a JSON object with an `error` string
 */
export function extractTokenError(
  tokenResponse: TokenRequestResponse | undefined,
): string | undefined {
  const err = tokenResponse?.error;
  if (!(err instanceof UnexpectedStatusCodeError)) {
    return undefined;
  }
  const parsed = oauthErrorBodySchema.safeParse(
    (() => {
      if (typeof err.reason === "object") {
        return err.reason;
      }
      try {
        return JSON.parse(err.reason ?? "");
      } catch {
        return undefined;
      }
    })(),
  );
  return parsed.success ? parsed.data.error : undefined;
}
