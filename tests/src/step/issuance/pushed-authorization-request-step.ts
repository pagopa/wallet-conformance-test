import { partialCallbacks } from "@/logic/utils";
import { StepFlow, StepResult } from "../step-flow";
import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
  JwtSignerJwk,
  PushedAuthorizationResponse,
} from "@pagopa/io-wallet-oauth2";

export type PushedAuthorizationRequestOptions = {
  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  attestation?: string;

  /**
   * DPoP JWT used to authenticate the client,
   * if not provided, the DPoP will be created using the wallet attestation
   */
  attestationPoP?: string;

  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   */
  clientId?: string;

  /**
   * Pushed Authorization Request Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  pushedAuthorizationRequestEndpoint?: string;
};

export type PushedAuthorizationRequestStepOptions = {
  attestation: string;
  attestationPoP: string;
  clientId: string;
  pushedAuthorizationRequestEndpoint: string;
} & CreatePushedAuthorizationRequestOptions;

export type PushedAuthorizationRequestExecuteResponse =
  PushedAuthorizationResponse;

export type PushedAuthorizationRequestResponse = StepResult & {
  response?: PushedAuthorizationResponse;
};

export class PushedAuthorizationRequestStep extends StepFlow {
  tag = "PUSHED_AUTHORIZATION_REQUEST";

  async run(
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting PushedAuthorizationRequest Step`);

    return this.execute<PushedAuthorizationRequestExecuteResponse>(async () => {
      log.info(
        `Sending PAR request to ${options.pushedAuthorizationRequestEndpoint}`,
      );
      const pushedAuthorizationRequestSigned =
        await createPushedAuthorizationRequest(options);

      const fetchOptions: fetchPushedAuthorizationResponseOptions = {
        callbacks: partialCallbacks,
        clientAttestationDPoP: options.attestationPoP,
        pushedAuthorizationRequestEndpoint:
          options.pushedAuthorizationRequestEndpoint,
        pushedAuthorizationRequestSigned,
        walletAttestation: options.attestation,
      };

      log.debug(`Fetching PAR response from ${JSON.stringify(fetchOptions)}`);

      return await fetchPushedAuthorizationResponse(fetchOptions);
    });
  }
}
