import {
  AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
} from "@pagopa/io-wallet-oid4vci";
import {
  AuthorizationRequestObject,
  createAuthorizationResponse,
  CreateAuthorizationResponseOptions,
  parseAuthorizeRequest,
} from "@pagopa/io-wallet-oid4vp";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";
import { DcqlQuery } from "dcql";

import { buildVpToken } from "@/logic";
import { getEncryptJweCallback, verifyJwt } from "@/logic/jwt";
import { fetchWithRetries, partialCallbacks } from "@/logic/utils";
import { AttestationResponse, CredentialWithKey } from "@/types";

import { StepFlow, StepResponse } from "../step-flow";

export interface AuthorizeExecuteResponse {
  authorizeResponse?: AuthorizationResponse;
  iss: string;
  requestObject?: AuthorizationRequestObject;
  requestObjectJwt: string;
}

export interface AuthorizeStepOptions {
  /**
   * Authorization Endpoint URL
   */
  authorizationEndpoint: string;

  /**
   * Issuer Base URL
   */
  baseUrl: string;

  /**
   * Client ID of the OAuth2 Client
   * */
  clientId: string;

  /**
   * Credential tokens produced by the issuer
   */
  credentials: CredentialWithKey[];

  /**
   * Request URI obtained from the Pushed Authorization Request step
   */
  requestUri?: string;

  /**
   * RP Metadata to be included in the Authorization Response
   */
  rpMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Wallet Attestation used to authenticate the client, it will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type AuthorizeStepResponse = StepResponse & {
  response?: AuthorizeExecuteResponse;
};

/**
 * Flow step to perform the authorization request to the issuer's authorization endpoint.
 * It constructs the authorization request, including the request object JWT,
 * and sends the request to obtain the authorization response.
 *
 * The response of this step includes:
 * - authorizeResponse: The authorization response from the issuer.
 * - iss: The issuer identifier.
 * - requestObject: The parsed authorization request object (if parsing was successful).
 * - requestObjectJwt: The raw authorization request object JWT as a string.
 */
export class AuthorizeDefaultStep extends StepFlow {
  tag = "AUTHORIZE";

  async run(options: AuthorizeStepOptions): Promise<AuthorizeStepResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Authorize Step`);

    const authorizeUrl = `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`;

    return this.execute<AuthorizeExecuteResponse>(async () => {
      log.info("Fetching Authorize Request from", authorizeUrl);
      const fetchAuthorize = await fetchWithRetries(
        authorizeUrl,
        this.config.network,
      );

      const requestObjectJwt = await fetchAuthorize.response.text();
      const parsedAuthorizeRequest = await parseAuthorizeRequest({
        callbacks: { verifyJwt },
        requestObjectJwt,
      });

      const requestObject = parsedAuthorizeRequest.payload;
      const responseUri = requestObject.response_uri;
      if (!responseUri) {
        log.error("Failed to obtain response uri from authorization request");
        throw new Error(
          "Failed to obtain response uri from authorization request",
        );
      }

      const rpEncKey = options.rpMetadata.jwks.keys.find(
        (key) => key.use === "enc",
      );
      if (!rpEncKey) {
        log.error("No encryption key found in RP Metadata JWKS");
        throw new Error("No encryption key found in RP Metadata JWKS");
      }

      const rpSigKey = options.rpMetadata.jwks.keys.find(
        (key) => key.use === "sig",
      );
      if (!rpSigKey) {
        log.error("No signature key found in RP Metadata JWKS");
        throw new Error("No signature key found in RP Metadata JWKS");
      }

      const dcqlQuery = requestObject.dcql_query as DcqlQuery | undefined;
      if (!dcqlQuery) {
        throw new Error("dcql_query is missing in the request object");
      }
      const vp_token = await buildVpToken(
        options.credentials,
        dcqlQuery,
        {
          client_id: options.clientId,
          nonce: requestObject.nonce,
          responseUri: responseUri,
        },
        this.log,
      );
      log.info("VP Token built successfully from DCQL query.");

      log.info("Creating Authorization Response...");
      log.debug(
        `Authorization response nonce: ${JSON.stringify({ nonce: requestObject.nonce })}`,
      );
      const createAuthorizationResponseOptions: CreateAuthorizationResponseOptions =
        {
          authorization_encrypted_response_alg:
            options.rpMetadata.authorization_encrypted_response_alg,
          authorization_encrypted_response_enc:
            options.rpMetadata.authorization_encrypted_response_enc,
          callbacks: {
            ...partialCallbacks,
            encryptJwe: getEncryptJweCallback(rpEncKey, {
              alg: options.rpMetadata.authorization_encrypted_response_alg,
              enc: options.rpMetadata.authorization_encrypted_response_enc,
              kid: rpEncKey.kid,
              typ: "oauth-authz-req+jwt",
            }),
          },
          requestObject,
          rpJwks: {
            jwks: options.rpMetadata.jwks,
          },
          vp_token,
        };

      const authorizationResponse = await createAuthorizationResponse(
        createAuthorizationResponseOptions,
      );
      if (!authorizationResponse.jarm) {
        log.error("Failed to create authorization response JARM");
        throw new Error("Failed to create authorization response JARM");
      }

      log.info(`Sending authorization response to: ${responseUri}`);
      log.debug(`Authorization response iss: ${options.baseUrl}`);
      const sendAuthorizationResponseAndExtractCodeOptions = {
        authorizationResponseJarm: authorizationResponse.jarm.responseJwe,
        callbacks: {
          verifyJwt,
        },
        iss: options.baseUrl,
        presentationResponseUri: responseUri,
        signer: {
          alg: "ES256",
          method: "jwk" as const,
          publicJwk: rpSigKey,
        },
        state: requestObject.state,
      };

      const authorizeResponse = await sendAuthorizationResponseAndExtractCode(
        sendAuthorizationResponseAndExtractCodeOptions,
      );

      return {
        authorizeResponse,
        iss: options.baseUrl,
        requestObject,
        requestObjectJwt,
      };
    });
  }
}
