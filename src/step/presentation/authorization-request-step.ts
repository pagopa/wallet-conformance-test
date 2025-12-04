import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  type AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
} from "@pagopa/io-wallet-oid4vci";
import {
  type AuthorizationRequestObject,
  createAuthorizationResponse,
  fetchAuthorizationRequest,
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
  authorizationResponse: AuthorizationResponse;
  parsedQrCode: ParsedQrCode;
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

      const verifierKey = options.rpMetadata.jwks.keys.find(
        (key) => key.use === "enc",
      );

      if (!verifierKey) {
        throw new Error("no encryption key found in verifier metadata");
      }

      const { unitKey } = options.walletAttestation;

      const credentialsWithKb = await Promise.all(
        [...options.credentials, options.walletAttestation.attestation].map(
          (sdJwt) =>
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

      const signer = {
        alg: "ES256",
        method: "jwk" as const,
        publicJwk: unitKey.publicKey,
      };

      const authorizationResponseResult = await createAuthorizationResponse({
        callbacks: {
          ...partialCallbacks,
          encryptJwe: getEncryptJweCallback(verifierKey, {
            alg: options.rpMetadata.authorization_encrypted_response_alg,
            enc: options.rpMetadata.authorization_encrypted_response_enc,
            kid: verifierKey.kid,
            typ: "oauth-authz-req+jwt",
          }),
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        client_id: parsedQrCode.clientId,
        requestObject,
        rpMetadata: options.rpMetadata,
        signer,
        vp_token: vpToken,
      });

      if (!authorizationResponseResult.jarm) {
        throw new Error(
          "JARM response is missing in the authorization response",
        );
      }

      const authorizationResponse =
        await sendAuthorizationResponseAndExtractCode({
          authorizationResponseJarm:
            authorizationResponseResult.jarm.responseJwt,
          callbacks: {
            verifyJwt,
          },
          iss: unitKey.publicKey.kid,
          presentationResponseUri: responseUri,
          signer,
          state: requestObject.state,
        });

      return {
        authorizationResponse,
        parsedQrCode,
        requestObject,
      };
    });
  }
}
