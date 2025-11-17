import { JwtSigner, JwtSignerJwk } from "@pagopa/io-wallet-oauth2";
import {
  AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
  SendAuthorizationResponseAndExtractCodeOptions,
} from "@pagopa/io-wallet-oid4vci";
import {
  AuthorizationRequestObject,
  createAuthorizationResponse,
  CreateAuthorizationResponseOptions,
  parseAuthorizeRequest,
  ParseAuthorizeRequestOptions,
} from "@pagopa/io-wallet-oid4vp";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { fetchWithRetries, partialCallbacks } from "@/logic/utils";
import { AttestationResponse, KeyPair } from "@/types";

import { StepFlow, StepResult } from "../step-flow";

export interface AuthorizeRunStepResponse {
  authorizeResponse?: AuthorizationResponse;
  headers: Headers;
  requestObject?: AuthorizationRequestObject;
  requestObjectJwt?: string;
  status: number;
}

export interface AuthorizeStepOptions {
  /**
   * Authorization Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  authorizationEndpoint: string;

  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   *
   * */
  clientId: string;

  /**
   * DPoP JWT used to authenticate the client,
   * if not provided, the DPoP will be created using the wallet attestation
   */
  issuerPublicKey: KeyPair;

  /**
   * Request URI obtained from the Pushed Authorization Request step
   */
  requestUri: string;

  /**
   * RP Metadata to be included in the Authorization Response
   */
  rpMetadata?: ItWalletCredentialVerifierMetadata;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type AuthorizeStepResponse = StepResult & {
  response?: AuthorizeRunStepResponse;
};

/**
 * Flow step to perform the Authorization Request to obtain an authorization code.
 * It sends the request to the Authorization Endpoint using the Request URI obtained from the Pushed Authorization Request step.
 * The response contains the authorization code and other relevant information.
 * Base URI is taken from the configuration.
 *
 */
export class AuthorizeDefaultStep extends StepFlow {
  tag = "AUTHORIZE";

  async run(options: AuthorizeStepOptions): Promise<AuthorizeStepResponse> {
    return this.execute<AuthorizeRunStepResponse>(async () => {
      const log = this.log.withTag(this.tag);

      log.info(`Starting Authorize Step`);

      const authorizeRequestUrl = `${options.authorizationEndpoint}?request_uri=${options.requestUri}&client_id=${options.clientId}`;

      log.info(`Authorize Request URL: ${authorizeRequestUrl}`);

      const { attempts, response } = await fetchWithRetries(
        authorizeRequestUrl,
        this.config.network,
      );
      const responseBody = await response.text();

      log.debug(
        `Request completed with status ${response.status} after ${attempts} failed attempts`,
      );

      const callbacks = {
        ...partialCallbacks,
      };

      const { issuerPublicKey } = options;

      let requestObject: AuthorizationRequestObject;
      try {
        requestObject = await parseAuthorizeRequest({
          callbacks: callbacks as ParseAuthorizeRequestOptions["callbacks"],
          dpop: {
            signer: {
              alg: "ES256",
              method: "jwk",
              publicJwk: {
                ...issuerPublicKey.publicKey,
                kid: issuerPublicKey.publicKey.kid!,
              },
            },
          },
          requestObjectJwt: responseBody,
        });
      } catch (e) {
        log.info("Failed to parse authorize request: ", e);
        throw new Error(
          "Failed to parse authorize request object from response",
        );
      }

      log.debug("Authorize Request Object:", requestObject);

      const { unitKey } = options.walletAttestation;
      const signer = {
        alg: "ES256",
        method: "jwk",
        publicJwk: {
          ...unitKey.publicKey,
          kid: unitKey.publicKey.kid!,
        },
      } as JwtSignerJwk;

      if (!options.rpMetadata) {
        log.error("RP Metadata is required but not provided");
        throw new Error("RP Metadata is required but not provided");
      }
      const createAuthResponse = await createAuthorizationResponse({
        callbacks: callbacks as CreateAuthorizationResponseOptions["callbacks"],
        client_id: unitKey.publicKey.kid,
        requestObject,
        rpMetadata: options.rpMetadata,
        signer,
        vp_token: [],
      });

      if (!createAuthResponse.jarm) {
        log.error("Failed to create authorization response JARM");
        throw new Error("Failed to create authorization response JARM");
      }

      const authorizeResponse = await sendAuthorizationResponseAndExtractCode({
        authorizationResponseJarm: createAuthResponse.jarm?.responseJwt,
        callbacks:
          callbacks as SendAuthorizationResponseAndExtractCodeOptions["callbacks"],
        iss: unitKey.publicKey.kid,
        presentationResponseUri: requestObject.response_uri!,
        signer,
        state: requestObject.state,
      });

      return {
        authorizeResponse,
        headers: response.headers,
        requestObject,
        requestObjectJwt: responseBody,
        status: response.status,
      };
    });
  }
}
