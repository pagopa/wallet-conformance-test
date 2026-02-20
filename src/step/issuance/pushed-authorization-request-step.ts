import {
  CreatePushedAuthorizationRequestOptions,
  PushedAuthorizationResponse,
} from "@pagopa/io-wallet-oauth2";

import { StepFlow, StepResponse } from "@/step";
import { AttestationResponse } from "@/types";

export type PushedAuthorizationRequestExecuteResponse =
  PushedAuthorizationResponse & {
  /**
   * Code verifier used in the Pushed Authorization Request, it will be generated internally
   */
  codeVerifier: string;

  };

export type PushedAuthorizationRequestResponse = StepResponse & {

  response?: PushedAuthorizationRequestExecuteResponse;
};

export interface PushedAuthorizationRequestStepOptions {
  /**
   * Client ID of the OAuth2 Client, it will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  /**
   * Code verifier used in the Pushed Authorization Request, it will be generated internally
   */
  codeVerifier?: string;

  /**
   * Optional overrides for CreatePushedAuthorizationRequestOptions.
   * When provided, these values will be spread over the computed defaults,
   * allowing tests to override any PAR parameter (e.g. clientId, audience, redirectUri).
   */
  createParOverrides?: Partial<CreatePushedAuthorizationRequestOptions>;

  /**
   * Credential Configuration ID for the requested credential
   */
  credentialConfigurationId: string;

  /**
   * DPoP JWT used to authenticate the client, it will be created using the wallet attestation
   */
  popAttestation: string;

  /**
   * Pushed Authorization Request Endpoint URL, it will be loaded from the issuer metadata
   */
  pushedAuthorizationRequestEndpoint: string;

  /**
   * Wallet Attestation used to authenticate the client, it will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

/**
 * Flow step to send a pushed authorization request to the issuer's pushed authorization request endpoint.
 * It uses the wallet attestation to authenticate the client and requests a credential using the specified
 * credential configuration ID.
 *
 * The response of this step includes the pushed authorization response containing the request URI and other details.
 */
export class PushedAuthorizationRequestDefaultStep extends StepFlow {
  tag = "PUSHED_AUTHORIZATION_REQUEST";

  async run(
    _: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
