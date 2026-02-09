import { CredentialResponse } from "@pagopa/io-wallet-oid4vci";

import { StepFlow, StepResult } from "@/step";
import { AttestationResponse, KeyPair } from "@/types";

export type CredentialRequestExecuteResponse = CredentialResponse;

export type CredentialRequestResponse = StepResult & {
  response?: CredentialResponse & {
    credentialKeyPair?: KeyPair;
  };
};

export interface CredentialRequestStepOptions {
  /**
   * Access Token fetched during the TokenRequestStep
   */
  accessToken: string;

  /**
   * Client ID of the OAuth2 Client, it will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  /**
   * Identifier of the credential to request, used to select the credential from the issuer metadata,
   */
  credentialIdentifier: string;

  /**
   * Credential Request Endpoint URL, it will be loaded from the issuer metadata
   */
  credentialRequestEndpoint: string;

  /**
   * Nonce fetched during the NonceRequestStep
   */
  nonce: string;

  /**
   * Wallet Attestation used to authenticate the client, it will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

/**
 * Flow step to request a credential from the issuer's credential endpoint.
 * It uses the access token obtained in the Token Request Step and the nonce from the Nonce Request Step.
 */
export class CredentialRequestDefaultStep extends StepFlow {
  tag = "CREDENTIAL_REQUEST";

  async run(
    _: CredentialRequestStepOptions,
  ): Promise<CredentialRequestResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
