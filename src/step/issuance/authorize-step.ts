import {
  AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
} from "@pagopa/io-wallet-oid4vci";
import {
  createAuthorizationResponse,
  CreateAuthorizationResponseVersionedOptions,
  parseAuthorizeRequest,
  ParsedAuthorizeRequestResult,
} from "@pagopa/io-wallet-oid4vp";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";
import { DcqlQuery } from "dcql";
import { exec } from "node:child_process";
import { platform } from "node:os";

import { startCallbackServer } from "@/logic/callback-server";
import { getCallbackRedirectUri } from "@/logic/constants";
import { getEncryptJweCallback, verifyJwt } from "@/logic/jwt";
import { fetchWithRetries, partialCallbacks } from "@/logic/utils";
import { buildVpToken } from "@/logic/vpToken";
import { AttestationResponse, CredentialWithKey } from "@/types";

import { StepFlow, StepResponse } from "../step-flow";

export interface AuthorizeExecuteResponse {
  authorizeResponse?: AuthorizationResponse;
  iss: string;
  requestObject?: ParsedAuthorizeRequestResult["payload"];
  requestObjectJwt?: string;
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
   * thumprint of the client public key used to sign the authorization response,
   * thumprint of the jwk in the cnf wallet attestation
   */
  clientId: string;

  /**
   * Identifier of the credential being issued
   */
  credentialIdentifier: string;

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
 * Opens the issuer's authorization URL in the system browser, starts a local
 * HTTP callback server, and waits for the OAuth2 authorization code redirect.
 *
 * The response of this step includes:
 * - authorizeResponse: The authorization response from the issuer (code, iss, state).
 * - iss: The issuer identifier.
 */
export class AuthorizeDefaultStep extends StepFlow {
  static readonly tag = "AUTHORIZE";

  async handlePidFlow({
    authorizeUrl,
    callbackPort,
    redirectUri,
  }: {
    authorizeUrl: string;
    callbackPort: number;
    redirectUri: string;
  }): Promise<AuthorizeExecuteResponse> {
    this.log.debug(`Starting callback server on ${redirectUri}`);
    const callbackPromise = startCallbackServer(callbackPort);

    this.log.info(`Opening browser at: ${authorizeUrl}`);
    openBrowser(authorizeUrl);

    this.log.info(
      "Waiting for the authorization callback... Complete the authentication flow in your browser.",
    );
    const authorizeResponse = await callbackPromise;

    this.log.debug(
      "Authorization callback received:",
      JSON.stringify(authorizeResponse, null, 2),
    );

    return {
      authorizeResponse,
      iss: authorizeResponse.iss,
    };
  }

  async handleQEEAFlow({
    authorizeUrl,
    options,
  }: {
    authorizeUrl: string;
    options: AuthorizeStepOptions;
  }): Promise<AuthorizeExecuteResponse> {
    const fetchAuthorize = await fetchWithRetries(
      authorizeUrl,
      this.config.network,
    );

    const requestObjectJwt = await fetchAuthorize.response.text();
    this.log.debug("Request Object JWT fetched successfully", requestObjectJwt);
    const parsedAuthorizeRequest = await parseAuthorizeRequest({
      callbacks: { verifyJwt },
      config: this.ioWalletSdkConfig,
      requestObjectJwt,
    });
    this.log.debug(
      "Parsed Authorize Request:",
      JSON.stringify(parsedAuthorizeRequest, null, 2),
    );

    const requestObject = parsedAuthorizeRequest.payload;
    const responseUri = requestObject.response_uri;
    if (!responseUri) {
      this.log.error(
        "Failed to obtain response uri from authorization request",
      );
      throw new Error(
        "Failed to obtain response uri from authorization request",
      );
    }

    const rpEncKey = options.rpMetadata.jwks.keys.find(
      (key) => key.use === "enc",
    );
    if (!rpEncKey) {
      this.log.error("No encryption key found in RP Metadata JWKS");
      throw new Error("No encryption key found in RP Metadata JWKS");
    }

    const rpSigKey = options.rpMetadata.jwks.keys.find(
      (key) => key.use === "sig",
    );
    if (!rpSigKey) {
      this.log.error("No signature key found in RP Metadata JWKS");
      throw new Error("No signature key found in RP Metadata JWKS");
    }

    const dcqlQuery = requestObject.dcql_query as DcqlQuery | undefined;
    if (!dcqlQuery) {
      throw new Error("dcql_query is missing in the request object");
    }

    if (!requestObject.state) {
      throw new Error("state is missing in the authorization request object");
    }

    const vp_token = await buildVpToken(
      options.credentials,
      dcqlQuery,
      {
        client_id: requestObject.client_id,
        nonce: requestObject.nonce,
        responseUri: responseUri,
      },
      this.config.wallet.wallet_version,
      this.log,
    );
    this.log.info("VP Token built successfully from DCQL query.");
    this.log.debug("VP Token built:", JSON.stringify(vp_token, null, 2));

    this.log.info("Creating Authorization Response...");
    this.log.debug(
      `Authorization response nonce: ${JSON.stringify({ nonce: requestObject.nonce })}`,
    );
    const createAuthorizationResponseOptions = {
      authorization_encrypted_response_alg:
        options.rpMetadata.authorization_encrypted_response_alg,
      authorization_encrypted_response_enc:
        options.rpMetadata.authorization_encrypted_response_enc,
      callbacks: {
        ...partialCallbacks,
        encryptJwe: getEncryptJweCallback(),
      },
      config: this.ioWalletSdkConfig,
      requestObject,
      rpJwks: {
        jwks: options.rpMetadata.jwks,
      },
      vp_token,
    } as CreateAuthorizationResponseVersionedOptions;

    const authorizationResponse = await createAuthorizationResponse(
      createAuthorizationResponseOptions,
    );
    this.log.debug(
      "Authorization Response created:",
      JSON.stringify(authorizationResponse, null, 2),
    );
    if (!authorizationResponse.jarm) {
      this.log.error("Failed to create authorization response JARM");
      throw new Error("Failed to create authorization response JARM");
    }

    this.log.info(`Sending authorization response to: ${responseUri}`);
    this.log.debug(`Authorization response iss: ${options.baseUrl}`);
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
    this.log.debug(
      "Authorize response extracted code:",
      JSON.stringify(authorizeResponse, null, 2),
    );

    return {
      authorizeResponse,
      iss: options.baseUrl,
      requestObject,
      requestObjectJwt,
    };
  }

  async run(options: AuthorizeStepOptions): Promise<AuthorizeStepResponse> {
    this.log.debug(`Starting Authorize Step`);
    const callbackPort = this.config.issuance.callback_port;
    const redirectUri = getCallbackRedirectUri(callbackPort);

    const authorizeUrl =
      `${options.authorizationEndpoint}` +
      `?client_id=${encodeURIComponent(options.clientId)}` +
      `&request_uri=${encodeURIComponent(options.requestUri ?? "")}`;

    return this.execute<AuthorizeExecuteResponse>(async () => {
      if (options.credentialIdentifier === "dc_sd_jwt_pid") {
        return this.handlePidFlow({
          authorizeUrl,
          callbackPort,
          redirectUri,
        });
      }

      return this.handleQEEAFlow({
        authorizeUrl,
        options,
      });
    });
  }

  tag(): string {
    return AuthorizeDefaultStep.tag;
  }
}

/** Opens the given URL in the system default browser (cross-platform). */
function openBrowser(url: string): void {
  const os = platform();
  let command: string;
  if (os === "darwin") {
    command = `open "${url}"`;
  } else if (os === "win32") {
    command = `start "" "${url}"`;
  } else {
    command = `xdg-open "${url}"`;
  }
  exec(command, (err) => {
    if (err) {
      // Non-fatal: the user can copy-paste the URL manually if the auto-open fails.
      console.warn(`Could not open browser automatically: ${err.message}`);
      console.warn(`Please open the following URL manually:\n  ${url}`);
    }
  });
}
