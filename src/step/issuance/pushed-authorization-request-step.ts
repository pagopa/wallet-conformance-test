import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
  PushedAuthorizationResponse,
} from "@pagopa/io-wallet-oauth2";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { StepFlow, StepResult } from "@/step";
import { AttestationResponse } from "@/types";

export type PushedAuthorizationRequestExecuteResponse =
  PushedAuthorizationResponse;

export interface PushedAuthorizationRequestOptions {
  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   */
  clientId?: string;

  /**
   * Code Verifier used in the PAR
   */
  codeVerifier: string;

  /**
   * DPoP JWT used to authenticate the client,
   * if not provided, the DPoP will be created using the wallet attestation
   */
  popAttestation: string;

  /**
   * Pushed Authorization Request Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  pushedAuthorizationRequestEndpoint?: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type PushedAuthorizationRequestResponse = StepResult & {
  response?: PushedAuthorizationRequestExecuteResponse;
};

export interface PushedAuthorizationRequestStepOptions {
  clientId: string;
  codeVerifier: string;
  credentialConfigurationId: string;
  popAttestation: string;
  pushedAuthorizationRequestEndpoint: string;
  walletAttestation: Omit<AttestationResponse, "created">;
}

export class PushedAuthorizationRequestDefaultStep extends StepFlow {
  tag = "PUSHED_AUTHORIZATION_REQUEST";

  async run(
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    return this.execute<PushedAuthorizationRequestExecuteResponse>(async () => {
      const log = this.log.withTag(this.tag);

      log.info(`Starting PushedAuthorizationRequest Step`);

      const { unitKey } = options.walletAttestation;

      const callbacks = {
        ...partialCallbacks,
        signJwt: signJwtCallback([unitKey.privateKey]),
      };

      const defaultCreateParOptions: CreatePushedAuthorizationRequestOptions = {
        audience: this.config.issuance.url,
        authorization_details: [
          {
            credential_configuration_id: options.credentialConfigurationId,
            type: "openid_credential",
          },
        ],
        callbacks:
          callbacks as CreatePushedAuthorizationRequestOptions["callbacks"],
        clientId: unitKey.publicKey.kid,
        codeChallengeMethodsSupported: ["S256"],
        dpop: {
          signer: {
            alg: "ES256",
            method: "jwk",
            publicJwk: unitKey.publicKey,
          },
        },
        pkceCodeVerifier: options.codeVerifier,
        redirectUri: "https://client.example.org/cb",
        responseMode: "query",
      };

      const createParOptions = {
        ...defaultCreateParOptions,
        ...options,
      };

      log.info(
        `Sending PAR request to ${options.pushedAuthorizationRequestEndpoint}`,
      );
      const pushedAuthorizationRequestSigned =
        await createPushedAuthorizationRequest(createParOptions);

      const fetchOptions: fetchPushedAuthorizationResponseOptions = {
        callbacks: partialCallbacks,
        clientAttestationDPoP: options.popAttestation,
        pushedAuthorizationRequestEndpoint:
          options.pushedAuthorizationRequestEndpoint,
        pushedAuthorizationRequestSigned,
        walletAttestation: options.walletAttestation.attestation,
      };

      log.debug(`Fetching PAR response from ${JSON.stringify(fetchOptions)}`);

      return fetchPushedAuthorizationResponse(fetchOptions);
    });
  }
}
