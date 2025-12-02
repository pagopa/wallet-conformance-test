import {
  AccessTokenRequest,
  AccessTokenResponse,
  createTokenDPoP,
  CreateTokenDPoPOptions,
  fetchTokenResponse,
  FetchTokenResponseOptions,
} from "@pagopa/io-wallet-oauth2";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { StepFlow, StepResult } from "@/step";
import { AttestationResponse } from "@/types";

export type TokenRequestExecuteResponse = AccessTokenResponse;

export type TokenRequestResponse = StepResult & {
  response?: AccessTokenResponse;
};

export interface TokenRequestStepOptions {
  accessTokenEndpoint: string;

  accessTokenRequest: AccessTokenRequest;

  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   */
  clientId?: string;
  /**
   * DPoP JWT used to authenticate the client,
   * if not provided, the DPoP will be created using the wallet attestation
   */
  popAttestation: string;
  redirectUri: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export class TokenRequestDefaultStep extends StepFlow {
  tag = "TOKEN_REQUEST";

  async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Token Request Step`);

    const { unitKey } = options.walletAttestation;

    return this.execute<TokenRequestExecuteResponse>(async () => {
      const createTokenDPoPOptions: CreateTokenDPoPOptions = {
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
          method: "POST",
          url: options.redirectUri,
        },
      };
      const tokenDPoP = await createTokenDPoP(createTokenDPoPOptions);

      const fetchTokenResponseOptions: FetchTokenResponseOptions = {
        accessTokenEndpoint: options.accessTokenEndpoint,
        accessTokenRequest: options.accessTokenRequest,
        callbacks: {
          fetch,
        },
        clientAttestationDPoP: options.popAttestation,
        dPoP: tokenDPoP.jwt,
        walletAttestation: options.walletAttestation.attestation,
      };
      return await fetchTokenResponse(fetchTokenResponseOptions);
    });
  }
}
