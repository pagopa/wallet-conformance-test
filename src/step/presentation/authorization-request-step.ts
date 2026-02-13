import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  type AuthorizationRequestObject,
  createAuthorizationResponse,
  type CreateAuthorizationResponseResult,
  fetchAuthorizationRequest,
  type Openid4vpAuthorizationRequestHeader,
  parseAuthorizeRequest,
  type ParsedQrCode,
} from "@pagopa/io-wallet-oid4vp";
import { DcqlQuery } from "dcql";

import type { AttestationResponse, CredentialWithKey } from "@/types";

import { getEncryptJweCallback, verifyJwt } from "@/logic/jwt";
import { partialCallbacks } from "@/logic/utils";
import { buildVpToken } from "@/logic/vpToken";
import { StepFlow, type StepResponse } from "@/step/step-flow";

export interface AuthorizationRequestExecuteStepResponse {
  authorizationRequestHeader: Openid4vpAuthorizationRequestHeader;
  authorizationResponse: CreateAuthorizationResponseResult;
  parsedQrCode: ParsedQrCode;
  requestObject: AuthorizationRequestObject;
  responseUri: string;
}

export interface AuthorizationRequestOptions {
  /**
   * Credentials along with their associated DPoP keys.
   */
  credentials: CredentialWithKey[];

  /**
   * Metadata about the verifier from the wallet's perspective.
   */
  verifierMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Attestation response from the wallet.
   */
  walletAttestation: AttestationResponse;
}

export type AuthorizationRequestStepResponse = StepResponse & {
  response?: AuthorizationRequestExecuteStepResponse;
};

/**
 * Implementation of the Authorization Request Step for OpenID4VP flow.
 * This step handles fetching the authorization request, building the VP token,
 * and creating the authorization response to be sent back to the verifier.
 */
export class AuthorizationRequestDefaultStep extends StepFlow {
  tag = "AUTHORIZATION";

  async run(
    options: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResponse> {
    const log = this.log.withTag(this.tag);
    log.info("Starting authorization request step...");

    return this.execute<AuthorizationRequestExecuteStepResponse>(async () => {
      const authorizeRequestUrl =
        this.config.presentation.authorize_request_url;
      log.info(`Fetching authorization request from: ${authorizeRequestUrl}`);
      const { parsedQrCode, requestObjectJwt } =
        await fetchAuthorizationRequest({
          authorizeRequestUrl,
          callbacks: { fetch },
        });

      const parsedAuthorizeRequest = await parseAuthorizeRequest({
        callbacks: { verifyJwt },
        requestObjectJwt,
      });

      const requestObject = parsedAuthorizeRequest.payload;
      log.info(
        `Authorization request fetched: ${JSON.stringify(requestObject)}.`,
      );

      const responseUri = requestObject.response_uri;
      if (!responseUri) {
        throw new Error("response_uri is missing in the request object");
      }

      const dcqlQuery = requestObject.dcql_query as DcqlQuery | undefined;
      if (!dcqlQuery) {
        throw new Error("dcql_query is missing in the request object");
      }
      const vp_token = await buildVpToken(
        options.credentials,
        dcqlQuery,
        {
          client_id: parsedQrCode.clientId,
          nonce: requestObject.nonce,
          responseUri: responseUri,
        },
        this.log,
      );
      log.info("VP Token built successfully from DCQL query.");

      const metadata = {
        ...options.verifierMetadata,
        authorization_encrypted_response_alg:
          options.verifierMetadata.authorization_encrypted_response_alg ||
          "ECDH-ES",
        authorization_encrypted_response_enc:
          options.verifierMetadata.authorization_encrypted_response_enc ||
          "A128CBC-HS256",
      };

      const {
        authorization_encrypted_response_alg,
        authorization_encrypted_response_enc,
        jwks,
      } = metadata;

      const encryptionKey = jwks.keys.find((k) => k.use === "enc");
      if (!encryptionKey) {
        throw new Error("no encryption key found in verifier metadata");
      }

      const authorizationResponse = await createAuthorizationResponse({
        authorization_encrypted_response_alg,
        authorization_encrypted_response_enc,
        callbacks: {
          ...partialCallbacks,
          encryptJwe: getEncryptJweCallback(encryptionKey, {
            alg: authorization_encrypted_response_alg,
            enc: authorization_encrypted_response_enc,
            kid: encryptionKey.kid,
            typ: "oauth-authz-req+jwt",
          }),
        },
        requestObject,
        rpJwks: {
          jwks: metadata.jwks,
        },
        vp_token,
      });

      return {
        authorizationRequestHeader: parsedAuthorizeRequest.header,
        authorizationResponse,
        parsedQrCode,
        requestObject,
        responseUri,
      };
    });
  }
}
