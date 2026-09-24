import {
  AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
  SendAuthorizationResponseAndExtractCodeOptions,
  verifyAuthorizationResponse,
  zAuthorizationResponse,
} from "@pagopa/io-wallet-oid4vci";
import {
  createAuthorizationResponse,
  type CreateAuthorizationResponseVersionedOptions,
  fetchAuthorizationResponse,
  parseAuthorizeRequest,
  type ParsedAuthorizeRequestResult,
} from "@pagopa/io-wallet-oid4vp";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";
import { DcqlQuery } from "dcql";
import { exec } from "node:child_process";
import { platform } from "node:os";

import { startCallbackServer } from "@/logic/callback-server";
import { getCallbackRedirectUri } from "@/logic/constants";
import { createVerifyJwtCallback, getEncryptJweCallback } from "@/logic/jwt";
import {
  fetchWithConfig,
  fetchWithRetries,
  partialCallbacksWithTrustAnchorUrls,
} from "@/logic/utils";
import { buildVpToken } from "@/logic/vpToken";
import { AttestationResponse, CredentialWithKey } from "@/types";

import type { IssuanceResponseMode } from "./pushed-authorization-request-step";

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
   * Effective OAuth/OID4VCI response mode selected during the PAR step.
   */
  responseMode?: IssuanceResponseMode;

  /**
   * RP Metadata to be included in the Authorization Response
   */
  rpMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * OAuth state generated for the PAR request.
   */
  state?: string;

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
      callbacks: {
        verifyJwt: createVerifyJwtCallback({
          trustAnchorUrls: this.config.trust.federation_trust_anchors,
        }),
      },
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
        ...partialCallbacksWithTrustAnchorUrls(
          this.config.trust.federation_trust_anchors,
        ),
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

    if (!options.state) {
      throw new Error("OAuth state from PAR is missing");
    }

    if (!options.responseMode) {
      throw new Error("OAuth response mode from PAR is missing");
    }

    const authorizeResponse = await this.completeQEEAFlow({
      authorizationResponseJarm: authorizationResponse.jarm.responseJwe,
      options,
      responseUri,
    });
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
      if (
        options.credentialIdentifier === "dc_sd_jwt_pid" ||
        options.credentialIdentifier === "dc_sd_jwt_eid"
      ) {
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

  private assertRedirectUriMatchesExpected(actual: URL, expected: URL): void {
    if (
      actual.protocol !== expected.protocol ||
      actual.hostname !== expected.hostname ||
      actual.port !== expected.port ||
      actual.pathname !== expected.pathname
    ) {
      throw new Error(
        `Unexpected authorization redirect_uri '${actual.toString()}'. Expected '${expected.protocol}//${expected.host}${expected.pathname}' ignoring query and fragment.`,
      );
    }
  }

  private async completeFormPostJwtFlow({
    authorizationResponseJarm,
    options,
    responseUri,
  }: {
    authorizationResponseJarm: string;
    options: AuthorizeStepOptions;
    responseUri: string;
  }): Promise<AuthorizationResponse> {
    const rpSigKey = options.rpMetadata.jwks.keys.find(
      (key) => key.use === "sig",
    );
    const sendAuthorizationResponseAndExtractCodeOptions = {
      authorizationResponseJarm,
      callbacks: {
        verifyJwt: createVerifyJwtCallback({
          trustAnchorUrls: this.config.trust.federation_trust_anchors,
        }),
      },
      iss: options.baseUrl,
      presentationResponseUri: responseUri,
      state: this.requireParState(options.state),
      ...(rpSigKey
        ? {
            signer: {
              alg: "ES256",
              method: "jwk",
              publicJwk: rpSigKey,
            },
          }
        : {}),
    } satisfies SendAuthorizationResponseAndExtractCodeOptions;

    return await sendAuthorizationResponseAndExtractCode(
      sendAuthorizationResponseAndExtractCodeOptions,
    );
  }

  private async completeQEEAFlow({
    authorizationResponseJarm,
    options,
    responseUri,
  }: {
    authorizationResponseJarm: string;
    options: AuthorizeStepOptions;
    responseUri: string;
  }): Promise<AuthorizationResponse> {
    if (options.responseMode === "form_post.jwt") {
      return this.completeFormPostJwtFlow({
        authorizationResponseJarm,
        options,
        responseUri,
      });
    }

    if (options.responseMode === "direct_post.jwt") {
      return this.completeDirectPostJwtFlow({
        authorizationResponseJarm,
        options,
        responseUri,
      });
    }

    throw new Error(
      `Unsupported OAuth response mode from PAR: ${String(options.responseMode)}`,
    );
  }

  private async completeDirectPostJwtFlow({
    authorizationResponseJarm,
    options,
    responseUri,
  }: {
    authorizationResponseJarm: string;
    options: AuthorizeStepOptions;
    responseUri: string;
  }): Promise<AuthorizationResponse> {
    this.log.debug("Completing direct_post.jwt flow for authorization response.");

    const { redirect_uri } = await fetchAuthorizationResponse({
      authorizationResponseJarm,
      callbacks: {
        fetch: fetchWithConfig(this.config.network),
      },
      presentationResponseUri: responseUri,
    });

    if (!redirect_uri) {
      throw new Error(
        "redirect_uri is missing in the direct_post.jwt authorization response",
      );
    }

    const redirectUri = new URL(redirect_uri);
    const expectedRedirectUri = new URL(
      getCallbackRedirectUri(this.config.issuance.callback_port),
    );
    this.assertRedirectUriMatchesExpected(redirectUri, expectedRedirectUri);

    const authorizationResponse = {
      code: redirectUri.searchParams.get("code"),
      iss: redirectUri.searchParams.get("iss"),
      state: redirectUri.searchParams.get("state"),
    };
    const missingParameters = Object.entries(authorizationResponse)
      .filter(([, value]) => !value)
      .map(([key]) => key);

    if (missingParameters.length > 0) {
      throw new Error(
        `Authorization redirect is missing parameter(s): ${missingParameters.join(", ")}`,
      );
    }

    const parsedAuthorizationResponse = zAuthorizationResponse.safeParse(
      authorizationResponse,
    );

    if (!parsedAuthorizationResponse.success) {
      throw new Error(
        `Invalid authorization response: ${parsedAuthorizationResponse.error.message}`,
      );
    }

    return await verifyAuthorizationResponse({
      authorizationResponse: parsedAuthorizationResponse.data,
      iss: options.baseUrl,
      state: this.requireParState(options.state),
    });
  }

  private requireParState(state: string | undefined): string {
    if (!state) {
      throw new Error("OAuth state from PAR is missing");
    }

    return state;
  }
}

/** Opens the given URL in the system default browser (cross-platform). */
function openBrowser(url: string): void {
  const os = platform();
  const quotedUrl = JSON.stringify(url);
  let command: string;
  if (os === "darwin") {
    command = `open ${quotedUrl}`;
  } else if (os === "win32") {
    command = `start "" ${quotedUrl}`;
  } else {
    command = `xdg-open ${quotedUrl}`;
  }
  exec(command, (err) => {
    if (err) {
      // Non-fatal: the user can copy-paste the URL manually if the auto-open fails.
      console.warn(`Could not open browser automatically: ${err.message}`);
      console.warn(`Please open the following URL manually:\n  ${url}`);
    }
  });
}
