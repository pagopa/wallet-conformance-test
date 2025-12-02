import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
  PushedAuthorizationResponse,
} from "@pagopa/io-wallet-oauth2";

import {
  createCredentialRequest,
  CredentialRequestOptions
} from "@pagopa/io-wallet-oid4vci";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { StepFlow, StepResult } from "@/step";
import { AttestationResponse } from "@/types";

export type CredentialRequestExecuteResponse =
  CredentialResponse;

export interface CredentialRequestStepOptions {
  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  /**
   * DPoP JWT used to authenticate the client,
   * if not provided, the DPoP will be created using the wallet attestation
   */
  popAttestation: string;

  /**
   * Pushed Authorization Request Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  credentialRequestEndpoint?: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type CredentialRequestResponse = StepResult & {
  response?: CredentialResponse;
};

export class CredentialRequestDefaultStep extends StepFlow {
  tag = "CREDENTIAL_REQUEST";

  async run(
    options: CredentialRequestStepOptions,
  ): Promise<CredentialRequestResponse> {
	const log = this.log.withTag(this.tag);

	log.info(`Starting Credential Request Step`);

	const { unitKey } = options.walletAttestation;

    return this.execute<CredentialRequestExecuteResponse>(async () => {
      const createCredentialRequestOptions: CredentialRequestOptions = {
        callbacks: {
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        clientId: options.clientId,
        credential_identifier: "",
        issuerIdentifier: "",
        nonce: "",
        signer: {
          alg: "ES256",
          method: "jwk",
          publicJwk: unitKey.publicKey,
        },
      };
      await createCredentialRequest(createCredentialRequestOptions)
    });
  }
}
