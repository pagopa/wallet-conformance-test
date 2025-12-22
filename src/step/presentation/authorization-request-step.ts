import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  type AuthorizationRequestObject,
  createAuthorizationResponse,
  type CreateOpenid4vpAuthorizationResponseResult,
  fetchAuthorizationRequest,
  type Openid4vpAuthorizationRequestHeader,
  type ParsedQrCode,
} from "@pagopa/io-wallet-oid4vp";

import type { AttestationResponse } from "@/types";

import {
  getEncryptJweCallback,
  partialCallbacks,
  signJwtCallback,
  verifyJwt,
} from "@/logic";
import { createVpTokenSdJwt } from "@/logic/sd-jwt";
import { StepFlow, type StepResult } from "@/step/step-flow";

export interface AuthorizationRequestOptions {
  authorizeRequestUrl: string;
  credentials: string[];
  verifierMetadata: ItWalletCredentialVerifierMetadata;
  walletAttestation: AttestationResponse;
}

export interface AuthorizationRequestStepResponse {
  authorizationRequestHeader: Openid4vpAuthorizationRequestHeader;
  authorizationResponse: CreateOpenid4vpAuthorizationResponseResult;
  parsedQrCode: ParsedQrCode;
  requestObject: AuthorizationRequestObject;
  responseUri: string;
}

export type AuthorizationRequestStepResult = StepResult & {
  response?: AuthorizationRequestStepResponse;
};

export class AuthorizationRequestDefaultStep extends StepFlow {
  tag = "AUTHORIZATION";

  async run(
    options: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResult> {
    const log = this.log.withTag(this.tag);
    log.info("Starting authorization request step...");

    return this.execute<AuthorizationRequestStepResponse>(async () => {
      const { parsedAuthorizeRequest, parsedQrCode } =
        await fetchAuthorizationRequest({
          authorizeRequestUrl: options.authorizeRequestUrl,
          callbacks: { verifyJwt },
        });

      const requestObject = parsedAuthorizeRequest.payload;

      const responseUri = requestObject.response_uri;
      if (!responseUri) {
        throw new Error("response_uri is missing in the request object");
      }

      const { unitKey } = options.walletAttestation;

      const credentialsWithKb = await Promise.all(
        options.credentials.map((sdJwt) =>
          createVpTokenSdJwt({
            client_id: parsedQrCode.clientId,
            dpopJwk: unitKey.privateKey,
            nonce: requestObject.nonce,
            sdJwt,
          }),
        ),
      );

      const vpToken = credentialsWithKb.reduce(
        (acc, credential, currIndex) => {
          acc[currIndex] = credential;
          return acc;
        },
        {} as Record<string, string>,
      );

      const {
        authorization_encrypted_response_alg,
        authorization_encrypted_response_enc,
        jwks,
      } = options.verifierMetadata;

      const verifierKeys = {
        enc: jwks.keys.find((k) => k.use === "enc"),
        sig: jwks.keys.find((k) => k.use === "sig"),
      };

      if (!verifierKeys.sig) {
        throw new Error("no signature key found in verifier metadata");
      }

      if (!verifierKeys.enc) {
        throw new Error("no encryption key found in verifier metadata");
      }

      const authorizationResponse = await createAuthorizationResponse({
        callbacks: {
          ...partialCallbacks,
          encryptJwe: getEncryptJweCallback(verifierKeys.enc, {
            alg: authorization_encrypted_response_alg,
            enc: authorization_encrypted_response_enc,
            kid: verifierKeys.enc.kid,
            typ: "oauth-authz-req+jwt",
          }),
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        client_id: parsedQrCode.clientId,
        requestObject,
        rpMetadata: options.verifierMetadata,
        vp_token: vpToken,
      });

      return {
        authorizationRequestHeader: parsedAuthorizeRequest.header,
        authorizationResponse,
        parsedQrCode,
        responseUri,
        requestObject
      };
    });
  }
}
