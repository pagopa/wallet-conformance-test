import {
  AccessTokenRequest,
  AccessTokenResponse,
} from "@pagopa/io-wallet-oauth2";

import { StepFlow, StepResult } from "@/step";
import { AttestationResponse } from "@/types";

export type TokenRequestExecuteResponse = AccessTokenResponse;

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

/**
 * Flow step to request an access token from the issuer's token endpoint.
 */
export class TokenRequestDefaultStep extends StepFlow {
  tag = "TOKEN_REQUEST";

  async run(_: TokenRequestStepOptions): Promise<TokenRequestResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
