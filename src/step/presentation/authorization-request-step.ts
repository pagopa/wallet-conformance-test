import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  type AuthorizationRequestObject,
  createAuthorizationResponse,
  fetchAuthorizationRequest,
  fetchAuthorizationResponse,
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
  rpMetadata: ItWalletCredentialVerifierMetadata;
  walletAttestation: Omit<AttestationResponse, "created">;
}

export type AuthorizationRequestStepResponse = StepResult & {
  response?: AuthorizationStepResponse;
};

export interface AuthorizationStepResponse {
  parsedQrCode: ParsedQrCode;
  redirectUri: string;
  requestObject: AuthorizationRequestObject;
}

export class AuthorizationRequestStep extends StepFlow {
  tag = "AUTHORIZATION";

  async run(
    options: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResponse> {
    const log = this.log.withTag(this.tag);
    log.info("Starting authorization request step...");

    return this.execute<AuthorizationStepResponse>(async () => {
      const { parsedQrCode, requestObject } = await fetchAuthorizationRequest({
        authorizeRequestUrl: options.authorizeRequestUrl,
        callbacks: { verifyJwt },
      });

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
      } = options.rpMetadata;

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

      const authorizationResponseResult = await createAuthorizationResponse({
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
        rpMetadata: options.rpMetadata,
        vp_token: vpToken,
      });

      if (!authorizationResponseResult.jarm) {
        throw new Error(
          "JARM response is missing in the authorization response",
        );
      }

      const { redirect_uri } = await fetchAuthorizationResponse({
        authorizationResponseJarm: authorizationResponseResult.jarm.responseJwt,
        callbacks: {
          ...partialCallbacks.fetch,
        },
        presentationResponseUri: responseUri,
      });

      return {
        parsedQrCode,
        redirectUri: redirect_uri,
        requestObject,
      };
    });
  }
}
