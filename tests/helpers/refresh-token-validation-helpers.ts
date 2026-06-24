import { buildTamperedPopJwt } from "#/helpers/par-validation-helpers";
import { createTokenDPoP, Jwk, JwtSignerJwk } from "@pagopa/io-wallet-oauth2";
import { exportJWK, generateKeyPair } from "jose";
import { randomUUID } from "node:crypto";

import type {
  TokenRequestResponse,
  TokenRequestStepOptions,
} from "@/step/issuance";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { TokenRequestDefaultStep } from "@/step/issuance";
import { KeyPairJwk } from "@/types";

const wrongClientAttestationPopAudience = "https://attacker.example.com";

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
