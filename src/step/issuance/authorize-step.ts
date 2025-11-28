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
import { decodeProtectedHeader } from "jose";

import {
  fetchWithRetries,
  getEncryptJweCallback,
  partialCallbacks,
  signJwtCallback,
  verifyJwt,
} from "@/logic";
import { AttestationResponse } from "@/types";

import { StepFlow, StepResult } from "../step-flow";

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
   * Credential token produced by the issuer
   */
  personIdentificationData: string;

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

    // const rpKey = options.rpMetadata.jwks.keys.find((key) => key.use === "sig");
    // if (!rpKey) {
    //   log.error("No encryption key found in RP Metadata JWKS");
    //   throw new Error("No encryption key found in RP Metadata JWKS");
    // }

    return this.execute<AuthorizeExecuteResponse>(async () => {
      log.info("Fetching Authorize Request from", `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`);
      const fetchAuthorize = await fetchWithRetries(
        `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`,
        this.config.network,
      );
      //TODO: Repat the call, second time should not succeed

      const requestObjectJwt = await fetchAuthorize.response.text();
      const requestObjectHeaderJwt = decodeProtectedHeader(requestObjectJwt);
      let issuerPublicKey: Jwk;
      if (requestObjectHeaderJwt.jwk)
        issuerPublicKey = requestObjectHeaderJwt.jwk as unknown as Jwk;
      else if (requestObjectHeaderJwt.kid)
        issuerPublicKey = options.rpMetadata.jwks.keys.find(
          (key) => key.kid === requestObjectHeaderJwt.kid,
        ) as unknown as Jwk;
      else {
        log.error(
          `Missing both 'kid' and 'jwk' from the authorize request object ${JSON.stringify(requestObjectHeaderJwt)}`,
        );
        throw new Error(
          "Missing both 'kid' and 'jwk' from the authorize request object",
        );
      }

      let authorizeRequest: AuthorizationRequestObject;
      try {
        const parseAuthorizeRequestOptions: ParseAuthorizeRequestOptions = {
          callbacks: {
            verifyJwt,
          },
          dpop: {
            signer: {
              alg: "ES256",
              method: "jwk",
              publicJwk: issuerPublicKey,
            },
          },
          requestObjectJwt,
        };

        authorizeRequest = await parseAuthorizeRequest(
          parseAuthorizeRequestOptions,
        );
      log.info(JSON.stringify(authorizeRequest, null, 4))
      } catch (e) {
        log.info("Failed to parse authorize request: ", e);
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

      const rpMetadata = authorizeRequest.client_metadata as ItWalletCredentialVerifierMetadata
      const rpKey = rpMetadata.jwks.keys.find((key) => key.use === "enc");
      if (!rpKey) {
        log.error("No encryption key found in RP Metadata JWKS");
        throw new Error("No encryption key found in RP Metadata JWKS");
      }

      const signer = {
        alg: "ES256",
        method: "jwk" as const,
        publicJwk: unitKey.publicKey,
      };
      const createAuthorizationResponseOptions: CreateAuthorizationResponseOptions =
        {
          callbacks: {
            ...partialCallbacks,
            encryptJwe: getEncryptJweCallback(rpKey, {
              alg: rpMetadata.authorization_encrypted_response_alg,
              enc: rpMetadata.authorization_encrypted_response_enc,
              kid: rpKey.kid,
              typ: "oauth-authz-req+jwt",
            }),
            signJwt: signJwtCallback([unitKey.privateKey]),
          },
          client_id: options.clientId,
          requestObject: authorizeRequest,
          rpMetadata: options.rpMetadata,
          signer,
          vp_token: [options.personIdentificationData],
        };

      const authorizationResponse = await createAuthorizationResponse(
        createAuthorizationResponseOptions,
      );
      log.info(authorizationResponse)
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
