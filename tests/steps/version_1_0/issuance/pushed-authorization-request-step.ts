import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
} from "@pagopa/io-wallet-oauth2";

import { partialCallbacks, signJwtCallback } from "@/logic";
import {
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestExecuteResponse,
  PushedAuthorizationRequestResponse,
} from "@/step/issuance/pushed-authorization-request-step";
import { AttestationResponse } from "@/types";

export interface PushedAuthorizationRequestStepOptions {
  clientId: string;
  codeVerifier: string;
  credentialConfigurationIds: string[];
  popAttestation: string;
  pushedAuthorizationRequestEndpoint: string;
  walletAttestation: Omit<AttestationResponse, "created">;
}

export class PushedAuthorizationRequestITWallet1_0Step extends PushedAuthorizationRequestDefaultStep {
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
            audience: this.config.issuance.url,
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
