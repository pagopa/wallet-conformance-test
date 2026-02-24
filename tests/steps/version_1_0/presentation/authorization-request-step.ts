import {
  createAuthorizationResponse,
  fetchAuthorizationRequest,
  parseAuthorizeRequest,
} from "@pagopa/io-wallet-oid4vp";
import { DcqlQuery } from "dcql";

import { getEncryptJweCallback, partialCallbacks, verifyJwt } from "@/logic";
import { createVpTokenSdJwt } from "@/logic/sd-jwt";
import { buildVpToken } from "@/logic/vpToken";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestExecuteStepResponse,
  AuthorizationRequestOptions,
  AuthorizationRequestStepResponse,
} from "@/step/presentation/authorization-request-step";

export class AuthorizationRequestITWallet1_0Step extends AuthorizationRequestDefaultStep {
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

      const credentialsWithKb = await Promise.all(
        options.credentials.map(({ credential, dpopJwk }) =>
          createVpTokenSdJwt({
            client_id: parsedQrCode.clientId,
            dpopJwk,
            nonce: requestObject.nonce,
            sdJwt: credential,
          }),
        ),
      );

      const dcqlQuery = requestObject.dcql_query as DcqlQuery | undefined;
      if (!dcqlQuery) {
        throw new Error("dcql_query is missing in the request object");
      }

      const vpToken = await buildVpToken(credentialsWithKb, dcqlQuery);
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
        vp_token: vpToken,
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
