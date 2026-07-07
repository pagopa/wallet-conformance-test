import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  createAuthorizationResponse,
  type CreateAuthorizationResponseResult,
  type CreateAuthorizationResponseVersionedOptions,
  fetchAuthorizationRequest,
  type FetchAuthorizationRequestOptions,
  type Openid4vpAuthorizationRequestHeader,
  parseAuthorizeRequest,
  ParsedAuthorizeRequestResult,
  type ParsedQrCode,
} from "@pagopa/io-wallet-oid4vp";
import { DcqlQuery } from "dcql";

import type { AttestationResponse, CredentialWithKey } from "@/types";

import { getEncryptJweCallback, verifyJwt } from "@/logic/jwt";
import { fetchWithConfig, partialCallbacks } from "@/logic/utils";
import { buildVpToken } from "@/logic/vpToken";
import { StepFlow, type StepResponse } from "@/step/step-flow";

export interface AuthorizationRequestExecuteStepResponse {
  authorizationRequestHeader: Openid4vpAuthorizationRequestHeader;
  authorizationResponse: CreateAuthorizationResponseResult;
  authorizeRequestUrl: string;
  parsedQrCode: ParsedQrCode;
  requestObject: ParsedAuthorizeRequestResult["payload"];
  requestObjectFetch?: RequestObjectFetchDetails;
  responseUri: string;
  walletMetadata: WalletMetadata;
  walletNonce: string;
}

export interface AuthorizationRequestOptions {
  /**
   * Authorization request URL for this execution.
   */
  authorizeRequestUrl: string;

  /**
   * Credentials along with their associated DPoP keys.
   */
  credentials: CredentialWithKey[];

  /**
   * Metadata about the verifier from the wallet's perspective.
   */
  verifierMetadata?: ItWalletCredentialVerifierMetadata;

  /**
   * Attestation response from the wallet.
   */
  walletAttestation: AttestationResponse;
}

export type AuthorizationRequestStepResponse = StepResponse & {
  response?: AuthorizationRequestExecuteStepResponse;
};

interface RequestObjectFetchDetails {
  body?: string;
  contentType?: string;
  method: string;
  url: string;
}

type WalletMetadata = NonNullable<
  FetchAuthorizationRequestOptions["walletMetadata"]
>;

/**
 * Implementation of the Authorization Request Step for OpenID4VP flow.
 * This step handles fetching the authorization request, building the VP token,
 * and creating the authorization response to be sent back to the verifier.
 */
export class AuthorizationRequestDefaultStep extends StepFlow {
  static readonly tag = "AUTHORIZATION_REQUEST";

  async run(
    options: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResponse> {
    const log = this.log;
    log.debug("Starting authorization request step...");

    return this.execute<AuthorizationRequestExecuteStepResponse>(async () => {
      const authorizeRequestUrl = options.authorizeRequestUrl;

      log.info(`Fetching authorization request from: ${authorizeRequestUrl}`);

      const walletNonce = crypto.randomUUID();
      const walletMetadata = buildWalletMetadata();
      let requestObjectFetch: RequestObjectFetchDetails | undefined;

      const fetchCallback = fetchWithConfig(this.config.network, {
        onRequest: ({ body, headers, method, url }) => {
          requestObjectFetch = {
            body: typeof body === "string" ? body : undefined,
            contentType: headers.get("content-type") ?? undefined,
            method,
            url,
          };
        },
      });

      const { parsedQrCode, requestObjectJwt } =
        await fetchAuthorizationRequest({
          authorizeRequestUrl,
          callbacks: { fetch: fetchCallback },
          walletMetadata,
          walletNonce,
        });

      log.debug("Parsed QR Code:", JSON.stringify(parsedQrCode, null, 2));
      log.debug("Request Object JWT:", requestObjectJwt);

      const parsedAuthorizeRequest = await parseAuthorizeRequest({
        callbacks: { verifyJwt },
        config: this.ioWalletSdkConfig,
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
        this.config.wallet.wallet_version,
        this.log,
      );
      log.info("VP Token built successfully from DCQL query.");

      const authorizationResponse = await createAuthorizationResponse({
        authorization_encrypted_response_alg:
          options.verifierMetadata?.authorization_encrypted_response_alg ||
          undefined,
        authorization_encrypted_response_enc:
          options.verifierMetadata?.authorization_encrypted_response_enc ||
          undefined,
        callbacks: {
          ...partialCallbacks,
          encryptJwe: getEncryptJweCallback(),
        },
        config: this.ioWalletSdkConfig,
        requestObject,
        rpJwks: {
          encrypted_response_enc_values_supported: options.verifierMetadata
            ?.encrypted_response_enc_values_supported as string[] | undefined,
          jwks: options.verifierMetadata?.jwks ?? { keys: [] },
        },
        vp_token,
      } as CreateAuthorizationResponseVersionedOptions);
      log.debug(
        "Authorization Response created:",
        JSON.stringify(authorizationResponse, null, 2),
      );

      return {
        authorizationRequestHeader: parsedAuthorizeRequest.header,
        authorizationResponse,
        authorizeRequestUrl,
        parsedQrCode,
        requestObject,
        requestObjectFetch,
        responseUri,
        walletMetadata,
        walletNonce,
      };
    });
  }

  tag(): string {
    return AuthorizationRequestDefaultStep.tag;
  }
}

function buildWalletMetadata(): WalletMetadata {
  const walletClientIdPrefixesSupported = [
    "redirect_uri",
    "x509_san_dns",
    "x509_san_uri",
  ];

  const walletVpFormatsSupported: WalletMetadata["vp_formats_supported"] = {
    "dc+sd-jwt": {
      "kb-jwt_alg_values": ["ES256"],
      "sd-jwt_alg_values": ["ES256"],
    },
    mso_mdoc: {
      alg: ["ES256"],
    },
  };

  return {
    client_id_prefixes_supported: walletClientIdPrefixesSupported,
    request_object_signing_alg_values_supported: ["ES256"],
    response_modes_supported: ["direct_post.jwt"],
    response_types_supported: ["vp_token"],
    vp_formats_supported: walletVpFormatsSupported,
  };
}
