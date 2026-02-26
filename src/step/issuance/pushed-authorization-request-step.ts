import { PushedAuthorizationResponse } from "@pagopa/io-wallet-oauth2";
import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
} from "@pagopa/io-wallet-oauth2";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { StepFlow, StepResponse } from "@/step";
import { AttestationResponse } from "@/types";

export type PushedAuthorizationRequestExecuteResponse =
  PushedAuthorizationResponse;

export type PushedAuthorizationRequestResponse = StepResponse & {
  /**
   * Code verifier used in the Pushed Authorization Request, it will be generated internally
   */
  codeVerifier?: string;

  response?: PushedAuthorizationRequestExecuteResponse;
};

export interface PushedAuthorizationRequestStepOptions {
  baseUrl: string;
  clientId: string;
  codeVerifier?: string;
  credentialConfigurationIds: string[];
  popAttestation: string;
  pushedAuthorizationRequestEndpoint: string;
  walletAttestation: Omit<AttestationResponse, "created">;
}

export interface PushedAuthorizationRequestStepOptions {
  /**
   * Issuer Base URL
   */
  baseUrl: string;

  /**
   * Client ID of the OAuth2 Client, it will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  /**
   * Credential Configuration ID for the requested credential
   */
  credentialConfigurationIds: string[];

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
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    const codeVerifier = "example_code_verifier";

    const result =
      await this.execute<PushedAuthorizationRequestExecuteResponse>(
        async () => {
          const log = this.log.withTag(this.tag);

          log.info(`Starting PushedAuthorizationRequest Step`);

          const { unitKey } = options.walletAttestation;

          const callbacks = {
            ...partialCallbacks,
            signJwt: signJwtCallback([unitKey.privateKey]),
          };

          const createParOptions: CreatePushedAuthorizationRequestOptions = {
            audience: options.baseUrl,
            authorization_details: options.credentialConfigurationIds.map(
              (id) => ({
                credential_configuration_id: id,
                type: "openid_credential",
              }),
            ),
            authorizationServerMetadata: {
              require_signed_request_object: true,
            },
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
            pkceCodeVerifier: codeVerifier,
            redirectUri: "https://client.example.org/cb",
            responseMode: "query",
          };

          log.info(
            `Sending PAR request to ${options.pushedAuthorizationRequestEndpoint}`,
          );
          log.debug(
            `PAR request credentialConfigurationId: ${options.credentialConfigurationIds}`,
          );
          const pushedAuthorizationRequest =
            await createPushedAuthorizationRequest({
              ...createParOptions,
              authorizationServerMetadata: {
                require_signed_request_object: true,
              },
            });

          const fetchOptions: fetchPushedAuthorizationResponseOptions = {
            callbacks: partialCallbacks,
            clientAttestationDPoP: options.popAttestation,
            pushedAuthorizationRequest,
            pushedAuthorizationRequestEndpoint:
              options.pushedAuthorizationRequestEndpoint,
            walletAttestation: options.walletAttestation.attestation,
          };

          log.info(
            `Fetching PAR response from ${options.pushedAuthorizationRequestEndpoint}`,
          );

          log.info(`PKCE code verifier ${codeVerifier}`);

          return await fetchPushedAuthorizationResponse(fetchOptions);
        },
      );

    return {
      ...result,
      codeVerifier,
    };
  }
}
