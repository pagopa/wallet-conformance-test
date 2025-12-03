import { Jwk } from "@pagopa/io-wallet-oauth2";
import {
  AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
} from "@pagopa/io-wallet-oid4vci";
import {
  AuthorizationRequestObject,
  createAuthorizationResponse,
  CreateAuthorizationResponseOptions,
  parseAuthorizeRequest,
  ParseAuthorizeRequestOptions,
} from "@pagopa/io-wallet-oid4vp";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  fetchWithRetries,
  getEncryptJweCallback,
  partialCallbacks,
  signJwtCallback,
  verifyJwt,
} from "@/logic";
import { AttestationResponse } from "@/types";

import { StepFlow, StepResult } from "../step-flow";
import { createVpTokenSdJwt } from "@/logic/sd-jwt";

export interface AuthorizeExecuteResponse {
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
   * Credential tokens produced by the issuer
   */
  credentials: string[];

  /**
   * Request URI obtained from the Pushed Authorization Request step
   */
  requestUri: string;

  /**
   * RP Metadata to be included in the Authorization Response
   */
  rpMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type AuthorizeStepResponse = StepResult & {
  response?: AuthorizeExecuteResponse;
};

export class AuthorizeDefaultStep extends StepFlow {
  tag = "AUTHORIZE";

  async run(options: AuthorizeStepOptions): Promise<AuthorizeStepResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Authorize Step`);

    const { unitKey } = options.walletAttestation;

    return this.execute<AuthorizeExecuteResponse>(async () => {
      log.info(
        "Fetching Authorize Request from",
        `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`,
      );
      const fetchAuthorize = await fetchWithRetries(
        `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`,
        this.config.network,
      );

      const requestObjectJwt = await fetchAuthorize.response.text();

      let authorizeRequest: AuthorizationRequestObject;
      try {
        const parseAuthorizeRequestOptions: ParseAuthorizeRequestOptions = {
          callbacks: {
            verifyJwt,
          },
          requestObjectJwt,
        };

        authorizeRequest = await parseAuthorizeRequest(
          parseAuthorizeRequestOptions,
        );
      } catch (e) {
        log.info("Failed to parse authorize request:", e);
        throw new Error(
          "Failed to parse authorize request object from response",
        );
      }

      const responseUri = authorizeRequest.response_uri;
      if (!responseUri) {
        log.error("Failed to obtain response uri from authorization request");
        throw new Error(
          "Failed to obtain response uri from authorization request",
        );
      }

      const rpKey = options.rpMetadata.jwks.keys.find(
        (key) => key.use === "enc",
      );
      if (!rpKey) {
        log.error("No encryption key found in RP Metadata JWKS");
        throw new Error("No encryption key found in RP Metadata JWKS");
      }

      const signer = {
        alg: "ES256",
        method: "jwk" as const,
        publicJwk: unitKey.publicKey,
      };

      const credentialsWithKb = await Promise.all(options.credentials.map((sdJwt) => createVpTokenSdJwt({
        sdJwt, 
        dpopJwk: unitKey.privateKey,
        nonce: authorizeRequest.nonce,
        sd_hash: authorizeRequest.sd_hash,
        client_id: options.clientId,
      })));
      const wiaWithKb = await createVpTokenSdJwt({
        sdJwt: options.walletAttestation.attestation,
        dpopJwk: unitKey.privateKey,
        nonce: authorizeRequest.nonce,
        sd_hash: authorizeRequest.sd_hash,
        client_id: options.clientId,
      });

      /**
       * VP Token structure:
       * {
       *   "0": "<Credential 1 with KB-JWT>",
       *   "1": "<Credential 2 with KB-JWT>",
       *   ...
       *   "<N>": "<WIA with KB-JWT>"
       * }
       */
      const vp_token = credentialsWithKb.reduce((acc, credential, index) => ({
        ...acc,
          [index]: credential,
        }),
        { [options.credentials.length]: wiaWithKb } as Record<string, string>,
      );

      const createAuthorizationResponseOptions: CreateAuthorizationResponseOptions =
        {
          callbacks: {
            ...partialCallbacks,
            encryptJwe: getEncryptJweCallback(rpKey, {
              alg: options.rpMetadata.authorization_encrypted_response_alg,
              enc: options.rpMetadata.authorization_encrypted_response_enc,
              kid: rpKey.kid,
              typ: "oauth-authz-req+jwt",
            }),
            signJwt: signJwtCallback([unitKey.privateKey]),
          },
          client_id: options.clientId,
          requestObject: authorizeRequest,
          rpMetadata: options.rpMetadata,
          vp_token,
        };

      const authorizationResponse = await createAuthorizationResponse(
        createAuthorizationResponseOptions,
      );
      log.info(authorizationResponse);
      if (!authorizationResponse.jarm) {
        log.error("Failed to create authorization response JARM");
        throw new Error("Failed to create authorization response JARM");
      }

      const sendAuthorizationResponseAndExtractCodeOptions = {
        authorizationResponseJarm: authorizationResponse.jarm.responseJwt,
        callbacks: {
          verifyJwt,
        },
        iss: unitKey.publicKey.kid,
        presentationResponseUri: responseUri,
        signer,
        state: authorizeRequest.state,
      };

      return {
        authorizeResponse: await sendAuthorizationResponseAndExtractCode(
          sendAuthorizationResponseAndExtractCodeOptions,
        ),
        headers: fetchAuthorize.response.headers,
        requestObject: authorizeRequest,
        requestObjectJwt,
        status: fetchAuthorize.response.status,
      };
    });
  }
}
