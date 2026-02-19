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
  PushedAuthorizationRequestStepOptions,
} from "@/step/issuance/pushed-authorization-request-step";

export class PushedAuthorizationRequestITWallet1_0Step extends PushedAuthorizationRequestDefaultStep {

  async run(
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {

    return this.execute<PushedAuthorizationRequestExecuteResponse>(
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

          const finalParOptions = {
            ...createParOptions,
            ...options.createParOverrides,
          };

          log.info(
            `Sending PAR request to ${options.pushedAuthorizationRequestEndpoint}`,
          );
          log.debug(
            `PAR request credentialConfigurationId: ${options.credentialConfigurationId}`,
          );
          const pushedAuthorizationRequestSigned =
            await createPushedAuthorizationRequest(finalParOptions);

          const codeVerifier = pushedAuthorizationRequestSigned.pkceCodeVerifier;

          const fetchOptions: fetchPushedAuthorizationResponseOptions = {
            callbacks: partialCallbacks,
            clientAttestationDPoP: options.popAttestation,
            pushedAuthorizationRequestEndpoint:
              options.pushedAuthorizationRequestEndpoint,
            pushedAuthorizationRequestSigned,
            walletAttestation: options.walletAttestation.attestation,
          };

          log.info(
            `Fetching PAR response from ${options.pushedAuthorizationRequestEndpoint}`,
          );

          log.info(`PKCE code verifier ${codeVerifier}`);

          return {
            ...(await fetchPushedAuthorizationResponse(fetchOptions)),
            codeVerifier
          };
        },
      );
  }
}
