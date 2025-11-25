import { AttestationResponse } from "@/types";
import { AccessTokenRequest, AccessTokenResponse, createTokenDPoP, CreateTokenDPoPOptions, fetchTokenResponse, FetchTokenResponseOptions } from "@pagopa/io-wallet-oauth2";
import { StepFlow, StepResult } from "@/step";
import { partialCallbacks, signJwtCallback } from "@/logic";

export type TokenRequestExecuteResponse =
  AccessTokenResponse;

export interface TokenRequestStepOptions {
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

  accessTokenEndpoint: string;
  accessTokenRequest: AccessTokenRequest;
  redirectUri: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type TokenRequestResponse = StepResult & {
  response?: AccessTokenResponse;
};

export class TokenRequestDefaultStep extends StepFlow {
  tag = "TOKEN_REQUEST";

  async run(
    options: TokenRequestStepOptions,
  ): Promise<TokenRequestResponse> {
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
          url: options.redirectUri,
          method: "POST"
        }
      };
      const tokenDPoP = await createTokenDPoP(createTokenDPoPOptions);

      const fetchTokenResponseOptions: FetchTokenResponseOptions = {
        accessTokenEndpoint: options.accessTokenEndpoint,
        accessTokenRequest: options.accessTokenRequest,
        callbacks: {
          fetch: (input, init) => fetch(input, {...init, headers: { ...init?.headers, DPoP: tokenDPoP.jwt }})
        },
        clientAttestationDPoP: options.popAttestation,
        walletAttestation: options.walletAttestation.attestation,
      };
      return await fetchTokenResponse(fetchTokenResponseOptions);
    });
  }
}
