import { PushedAuthorizationResponse } from "@pagopa/io-wallet-oauth2";
import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
} from "@pagopa/io-wallet-oauth2";

import { PID_CREDENTIAL_CONFIGURATION_ID } from "@/errors";
import { fetchWithConfig, partialCallbacks, signJwtCallback } from "@/logic";
import { REDIRECT_URI } from "@/logic/constants";
import { StepFlow, StepResponse } from "@/step";
import { AttestationResponse } from "@/types";

export type PushedAuthorizationRequestExecuteResponse =
  PushedAuthorizationResponse & {
    /**
     * Code verifier used in the Pushed Authorization Request, if not provided it will be generated internally
     */
    codeVerifier: string;
  };

export type PushedAuthorizationRequestResponse = StepResponse & {
  response?: PushedAuthorizationRequestExecuteResponse;
};

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
   * Code verifier used in the Pushed Authorization Request, if not provided it will be generated internally
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
  static readonly tag = "PUSHED_AUTHORIZATION_REQUEST";

  /**
   * FR-10: PID-specific `authorization_details` entry.
   *
   * Returns an additional `authorization_details` entry when the PAR request
   * targets the PID credential configuration ID. Override in test subclasses
   * to inject negative test cases (e.g. wrong `type`, extra/missing fields).
   *
   * Returns `undefined` by default (no extra entry).
   */
  protected pidCredentialAuthorizationDetails():
    | {
        credential_configuration_id: string;
        type: string;
      }
    | undefined {
    return undefined;
  }

  async run(
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    return await this.execute<PushedAuthorizationRequestExecuteResponse>(
      async () => {
        const log = this.log;

        log.debug(`Starting PushedAuthorizationRequest Step`);

        const { unitKey } = options.walletAttestation;

        const callbacks = {
          ...partialCallbacks,
          fetch: fetchWithConfig(this.config.network),
          signJwt: signJwtCallback([unitKey.privateKey]),
        };

        const isPidRequest = options.credentialConfigurationIds.includes(
          PID_CREDENTIAL_CONFIGURATION_ID,
        );
        const pidEntry = isPidRequest
          ? this.pidCredentialAuthorizationDetails()
          : undefined;

        const allEntries = [
          ...options.credentialConfigurationIds.map((id) => ({
            credential_configuration_id: id,
            type: "openid_credential",
          })),
          ...(pidEntry ? [pidEntry] : []),
        ];

        const seen = new Set<string>();
        const authorization_details = allEntries.filter((entry) => {
          if (seen.has(entry.credential_configuration_id)) return false;
          seen.add(entry.credential_configuration_id);
          return true;
        });

        const createParOptions = {
          audience: options.baseUrl,
          authorization_details,
          // Hardcode require_signed_request_object to true as the wallet is expected to always sign the request object
          // We'll need to allow overriding this in case we want to test unsigned request objects in negative test cases
          authorizationServerMetadata: {
            require_signed_request_object: true,
          },
          callbacks:
            callbacks as CreatePushedAuthorizationRequestOptions["callbacks"],
          clientId: unitKey.publicKey.kid,
          codeChallengeMethodsSupported: ["S256"],
          config: this.ioWalletSdkConfig,
          dpop: {
            signer: {
              alg: "ES256",
              method: "jwk",
              publicJwk: unitKey.publicKey,
            },
          },
          pkceCodeVerifier: options.codeVerifier,
          redirectUri: REDIRECT_URI,
          responseMode: "query",
        };

        const finalParOptions = {
          ...createParOptions,
          ...options.createParOverrides,
        } as CreatePushedAuthorizationRequestOptions;

        log.debug(
          "Final PAR options:",
          JSON.stringify(finalParOptions, null, 2),
        );

        log.info(
          `Sending PAR request to ${options.pushedAuthorizationRequestEndpoint}`,
        );
        log.debug(
          `PAR request credentialConfigurationId: ${options.credentialConfigurationIds}`,
        );
        const pushedAuthorizationRequest =
          await createPushedAuthorizationRequest(finalParOptions);

        const codeVerifier = pushedAuthorizationRequest.pkceCodeVerifier;

        const fetchOptions: fetchPushedAuthorizationResponseOptions = {
          callbacks: callbacks,
          clientAttestationDPoP: options.popAttestation,
          pushedAuthorizationRequest,
          pushedAuthorizationRequestEndpoint:
            options.pushedAuthorizationRequestEndpoint,
          walletAttestation: options.walletAttestation.attestation,
        };

        log.info(
          `Fetching PAR response from ${options.pushedAuthorizationRequestEndpoint}`,
        );

        log.debug(`PKCE code verifier ${codeVerifier}`);

        const parResponse =
          await fetchPushedAuthorizationResponse(fetchOptions);
        log.debug("PAR response:", JSON.stringify(parResponse, null, 2));

        return {
          ...parResponse,
          codeVerifier,
        };
      },
    );
  }

  tag(): string {
    return PushedAuthorizationRequestDefaultStep.tag;
  }
}
