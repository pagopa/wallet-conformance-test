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

import {
  fetchWithRetries,
  getEncryptJweCallback,
  partialCallbacks,
  signJwtCallback,
  verifyJwt,
} from "@/logic";
import { createVpTokenSdJwt } from "@/logic/sd-jwt";
import { AttestationResponse } from "@/types";

import { StepFlow, StepResult } from "../step-flow";

export interface AuthorizeExecuteResponse {
  authorizeResponse?: AuthorizationResponse;
  requestObject?: AuthorizationRequestObject;
}

export interface AuthorizeStepOptions {
  /**
   * Authorization Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  authorizationEndpoint: string;

  /**
   * Base URL of the issuer.
   */
  baseUrl: string;

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
  requestUri?: string;

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
    const authorizeUrl = `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`;

    return this.execute<AuthorizeExecuteResponse>(async () => {
      log.info("Fetching Authorize Request from", authorizeUrl);
      const fetchAuthorize = await fetchWithRetries(
        authorizeUrl,
        this.config.network,
      );

      log.info("Performing redundant fetch");
      const redundantFetchAuthorize = await fetchWithRetries(
        authorizeUrl,
        this.config.network,
      );

      const requestObject = await parseAuthorizeRequest({
        callbacks: { verifyJwt },
        requestObjectJwt: await fetchAuthorize.response.text(),
      });

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

      const credentialsWithKb = await Promise.all(
        options.credentials.map((sdJwt) =>
          createVpTokenSdJwt({
            client_id: options.clientId,
            dpopJwk: unitKey.privateKey,
            nonce: requestObject.nonce,
            sdJwt,
          }),
        ),
      );
      const wiaWithKb = await createVpTokenSdJwt({
        client_id: options.clientId,
        dpopJwk: unitKey.privateKey,
        nonce: requestObject.nonce,
        sdJwt: options.walletAttestation.attestation,
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
      const vp_token = credentialsWithKb.reduce(
        (acc, credential, index) => ({
          ...acc,
          [index]: credential,
        }),
        { [options.credentials.length]: wiaWithKb } as Record<string, string>,
      );

      log.info("Creating Authorization Response...");
      const createAuthorizationResponseOptions: CreateAuthorizationResponseOptions =
        {
          callbacks: {
            ...partialCallbacks,
            encryptJwe: getEncryptJweCallback(rpEncKey, {
              alg: options.rpMetadata.authorization_encrypted_response_alg,
              enc: options.rpMetadata.authorization_encrypted_response_enc,
              kid: rpEncKey.kid,
              typ: "oauth-authz-req+jwt",
            }),
            signJwt: signJwtCallback([unitKey.privateKey]),
          },
          client_id: options.clientId,
          requestObject: requestObject,
          rpMetadata: options.rpMetadata,
          vp_token,
        };

      const authorizationResponse = await createAuthorizationResponse(
        createAuthorizationResponseOptions,
      );
      if (!authorizationResponse.jarm) {
        log.error("Failed to create authorization response JARM");
        throw new Error("Failed to create authorization response JARM");
      }

      log.info("Sending Authorization Response...");
      const sendAuthorizationResponseAndExtractCodeOptions = {
        authorizationResponseJarm: authorizationResponse.jarm.responseJwt,
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

      return {
        authorizeResponse: await sendAuthorizationResponseAndExtractCode(
          sendAuthorizationResponseAndExtractCodeOptions,
        ),
        requestObject: requestObject,
        retryStatus: redundantFetchAuthorize.response.status,
      };
    });
  }
}
