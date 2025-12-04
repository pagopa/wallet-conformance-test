import {
  createCredentialRequest,
  CredentialRequestOptions,
  CredentialResponse,
  fetchCredentialResponse,
  FetchCredentialResponseOptions,
} from "@pagopa/io-wallet-oid4vci";

import { signJwtCallback } from "@/logic";
import { StepFlow, StepResult } from "@/step";
import { AttestationResponse } from "@/types";

export type CredentialRequestExecuteResponse = CredentialResponse;

export type CredentialRequestResponse = StepResult & {
  response?: CredentialResponse;
};

export interface CredentialRequestStepOptions {
  accessToken: string;

  baseUrl: string;

  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  credentialIdentifier: string;

  /**
   * Credential Request Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  credentialRequestEndpoint: string;
  dpop: string;
  nonce: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

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
        credential_identifier: options.credentialIdentifier,
        issuerIdentifier: options.baseUrl,
        nonce: options.nonce,
        signer: {
          alg: "ES256",
          method: "jwk",
          publicJwk: unitKey.publicKey,
        },
      };
      const credentialRequest = await createCredentialRequest(
        createCredentialRequestOptions,
      );

      log.debug(
        `Fetching Credential response from ${options.credentialRequestEndpoint}`,
      );
      const fetchCredentialResponseOptions: FetchCredentialResponseOptions = {
        accessToken: options.accessToken,
        callbacks: {
          fetch,
        },
        credentialEndpoint: options.credentialRequestEndpoint,
        credentialRequest,
        dPoP: options.dpop,
      };
      return await fetchCredentialResponse(fetchCredentialResponseOptions);
    });
  }
}
