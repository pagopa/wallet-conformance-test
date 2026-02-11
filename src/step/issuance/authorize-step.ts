import { AuthorizationResponse } from "@pagopa/io-wallet-oid4vci";
import { AuthorizationRequestObject } from "@pagopa/io-wallet-oid4vp";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { AttestationResponse, KeyPair } from "@/types";

import { StepFlow, StepResult } from "../step-flow";

export interface AuthorizeExecuteResponse {
  authorizeResponse?: AuthorizationResponse;
  iss: string;
  requestObject?: AuthorizationRequestObject;
  requestObjectJwt: string;
}

export interface AuthorizeStepOptions {
  /**
   * Authorization Endpoint URL
   */
  authorizationEndpoint: string;

  /**
   * Client ID of the OAuth2 Client
   * */
  clientId: string;

  /**
   * Credential tokens produced by the issuer
   */
  credentials: { credential: string; keyPair: KeyPair }[];

  /**
   * Request URI obtained from the Pushed Authorization Request step
   */
  requestUri?: string;

  /**
   * RP Metadata to be included in the Authorization Response
   */
  rpMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Wallet Attestation used to authenticate the client, it will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type AuthorizeStepResponse = StepResult & {
  response?: AuthorizeExecuteResponse;
};

/**
 * Flow step to perform the authorization request to the issuer's authorization endpoint.
 * It constructs the authorization request, including the request object JWT,
 * and sends the request to obtain the authorization response.
 *
 * The response of this step includes:
 * - authorizeResponse: The authorization response from the issuer.
 * - iss: The issuer identifier.
 * - requestObject: The parsed authorization request object (if parsing was successful).
 * - requestObjectJwt: The raw authorization request object JWT as a string.
 */
export class AuthorizeDefaultStep extends StepFlow {
  tag = "AUTHORIZE";

  async run(_: AuthorizeStepOptions): Promise<AuthorizeStepResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
