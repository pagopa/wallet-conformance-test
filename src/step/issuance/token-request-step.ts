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
import { JWK } from "jose";

export type TokenRequestExecuteResponse = AccessTokenResponse & { dpopKey: JWK };

export type TokenRequestResponse = StepResult & {
  response?: TokenRequestExecuteResponse;
};

export interface TokenRequestStepOptions {
  /**
   * Access Token Endpoint URL
   */
  accessTokenEndpoint: string;

  /**
   * Body to be sent as part of the Access Token Request
   */
  accessTokenRequest: AccessTokenRequest;

  /**
   * DPoP JWT used to authenticate the client,
   * if not provided, the DPoP will be created using the wallet attestation
   */
  popAttestation: string;

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
          url: options.accessTokenEndpoint,
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
      return {
        ...await fetchTokenResponse(fetchTokenResponseOptions),
        dpopKey: tokenDPoP.signerJwk
      };
    });
  }
}
