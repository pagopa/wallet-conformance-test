import { sendAuthorizationResponseAndExtractCode } from "@pagopa/io-wallet-oid4vci";
import {
  createAuthorizationResponse,
  CreateAuthorizationResponseOptions,
  parseAuthorizeRequest,
} from "@pagopa/io-wallet-oid4vp";
import { DcqlQuery } from "dcql";

import {
  buildVpToken,
  createVpTokenMdoc,
  fetchWithRetries,
  getEncryptJweCallback,
  partialCallbacks,
  signJwtCallback,
  verifyJwt,
} from "@/logic";
import { createVpTokenSdJwt } from "@/logic/sd-jwt";
import {
  AuthorizeDefaultStep,
  AuthorizeExecuteResponse,
  AuthorizeStepOptions,
  AuthorizeStepResponse,
} from "@/step/issuance/authorize-step";

export class AuthorizeITWallet1_0Step extends AuthorizeDefaultStep {
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

      const credentialsWithKb = await Promise.all(
        options.credentials.map((c) =>
          c.typ === "dc+sd-jwt"
            ? createVpTokenSdJwt({
                client_id: options.clientId,
                dpopJwk: c.keyPair.privateKey,
                nonce: requestObject.nonce,
                sdJwt: c.credential,
              })
            : createVpTokenMdoc({
                clientId: options.clientId,
                credential: c.credential,
                devicePrivateKey: c.keyPair.privateKey,
                nonce: requestObject.nonce,
                responseUri: requestObject.response_uri ?? "",
              }),
        ),
      );

      const dcqlQuery = requestObject.dcql_query as DcqlQuery | undefined;
      if (!dcqlQuery) {
        throw new Error("dcql_query is missing in the request object");
      }

      const vp_token = await buildVpToken(credentialsWithKb, dcqlQuery);
      log.info("VP Token built successfully from DCQL query.");

      log.info("Creating Authorization Response...");
      log.debug(
        `Authorization response nonce: ${JSON.stringify({ nonce: requestObject.nonce })}`,
      );
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
          requestObject,
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

      const baseUrl = this.config.issuance.url;
      log.info(`Sending authorization response to: ${responseUri}`);
      log.debug(`Authorization response iss: ${baseUrl}`);
      const sendAuthorizationResponseAndExtractCodeOptions = {
        authorizationResponseJarm: authorizationResponse.jarm.responseJwt,
        callbacks: {
          verifyJwt,
        },
        iss: baseUrl,
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

      // log.info("Performing redundant fetch");
      // const redundantFetchAuthorize = await fetchWithRetries(
      //   authorizeUrl,
      //   this.config.network,
      // );

      return {
        authorizeResponse,
        iss: baseUrl,
        requestObject,
        requestObjectJwt,
        // retryStatus: redundantFetchAuthorize.response.status,
      };
    });
  }
}
