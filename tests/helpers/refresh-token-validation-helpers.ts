import { buildTamperedPopJwt } from "#/helpers/par-validation-helpers";
import { createTokenDPoP } from "@pagopa/io-wallet-oauth2";

import type {
  TokenRequestResponse,
  TokenRequestStepOptions,
} from "@/step/issuance";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { TokenRequestDefaultStep } from "@/step/issuance";

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
