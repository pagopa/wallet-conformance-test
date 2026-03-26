import {
  AccessTokenRequest,
  AccessTokenResponse,
  createTokenDPoP,
  CreateTokenDPoPOptions,
  fetchTokenResponse,
  FetchTokenResponseOptions,
} from "@pagopa/io-wallet-oauth2";

import {
  createKeys,
  fetchWithConfig,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { StepFlow, StepResponse } from "@/step";
import { AttestationResponse, KeyPair } from "@/types";

export type TokenRequestExecuteResponse = AccessTokenResponse & {
  /**
   * Ephemeral DPoP key pair generated for this issuance session.
   * This key MUST be reused in Credential Request for the DPoP proof there.
   */
  dPoPKey: KeyPair;
};

export type TokenRequestResponse = StepResponse & {
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
   * Client attestation DPoP JWT used to authenticate the client at the
   * Access Token Endpoint (derived from the wallet attestation flow).
   *
   * Note: this is NOT the DPoP key used for token binding. The token-binding
   * DPoP is always created in this step using a fresh ephemeral key pair and
   * returned as `dPoPKey` so it can be reused later in the flow.
   */
  popAttestation: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

/**
 * Flow step to request an access token from the issuer's token endpoint.
 */
export class TokenRequestDefaultStep extends StepFlow {
  tag = "TOKEN_REQUEST";

  async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.debug(`Starting Token Request Step`);

    return this.execute<TokenRequestExecuteResponse>(async () => {
      log.info("Generating ephemeral DPoP key pair...");
      const dPoPKey = await createKeys();

      log.info(`Fetching access token from: ${options.accessTokenEndpoint}`);
      const createTokenDPoPOptions: CreateTokenDPoPOptions = {
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([dPoPKey.privateKey]),
        },
        signer: {
          alg: "ES256",
          method: "jwk",
          publicJwk: dPoPKey.publicKey,
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
          fetch: fetchWithConfig(this.config.network),
        },
        clientAttestationDPoP: options.popAttestation,
        dPoP: tokenDPoP.jwt,
        walletAttestation: options.walletAttestation.attestation,
      };
      const tokenResponse = await fetchTokenResponse(fetchTokenResponseOptions);

      return {
        ...tokenResponse,
        dPoPKey,
      };
    });
  }
}
