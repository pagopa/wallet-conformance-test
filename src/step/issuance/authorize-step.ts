import {
  AuthorizationResponse,
  sendAuthorizationResponseAndExtractCode,
  SendAuthorizationResponseAndExtractCodeOptions,
  verifyAuthorizationResponse,
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

import { parseAuthorizationResponse } from "@/logic/authorization-response";
import { startCallbackServer } from "@/logic/callback-server";
import { getCallbackRedirectUri } from "@/logic/constants";
import { createVerifyJwtCallback, getEncryptJweCallback } from "@/logic/jwt";
import {
  fetchWithConfig,
  fetchWithRetries,
  partialCallbacks,
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
   * Effective redirect URI sent in the Pushed Authorization Request.
   */
  redirectUri?: string;

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

    const headless = isTruthyEnv(process.env.CONFIG_AUTHORIZE_HEADLESS);
    if (headless) {
      this.log.info(`Completing authorization headlessly at: ${authorizeUrl}`);
      await completeAuthorizeHeadless(authorizeUrl, this.log);
    } else {
      this.log.info(`Opening browser at: ${authorizeUrl}`);
      openBrowser(authorizeUrl);
      this.log.info(
        "Waiting for the authorization callback... Complete the authentication flow in your browser.",
      );
    }

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

  private async completeDirectPostJwtFlow({
    authorizationResponseJarm,
    options,
    responseUri,
  }: {
    authorizationResponseJarm: string;
    options: AuthorizeStepOptions;
    responseUri: string;
  }): Promise<AuthorizationResponse> {
    this.log.debug(
      "Completing direct_post.jwt flow for authorization response.",
    );

    const appFetch = fetchWithConfig(this.config.network);
    const { redirect_uri } = await fetchAuthorizationResponse({
      authorizationResponseJarm,
      callbacks: {
        ...partialCallbacks,
        fetch: appFetch,
      },
      presentationResponseUri: responseUri,
    });

    if (!redirect_uri) {
      const errorMessage =
        "The authorization server did not return a redirect_uri to continue the authorization flow";
      this.log.error(errorMessage);
      throw new Error(errorMessage);
    }

    const response = await appFetch(redirect_uri, { redirect: "manual" }).catch(
      () => null,
    );
    if (!response || response.status >= 400) {
      const errorMessage = `An error occurred while completing the authorization flow. Ensure ${redirect_uri} is a valid HTTP url for redirect`;
      this.log.error(errorMessage);
      throw new Error(errorMessage);
    }

    const finalRedirectUri = response.headers.get("location");
    if (!finalRedirectUri) {
      const errorMessage = `The authorization server did not redirect to the provided client redirect URI. got: ${finalRedirectUri}`;
      this.log.error(errorMessage);
      throw new Error(errorMessage);
    }

    const redirectUri = new URL(finalRedirectUri);

    if (!options.redirectUri) {
      throw new Error("Effective redirect URI from PAR is missing");
    }

    const expectedRedirectUri = new URL(options.redirectUri);
    if (
      redirectUri.protocol !== expectedRedirectUri.protocol ||
      redirectUri.hostname !== expectedRedirectUri.hostname ||
      redirectUri.port !== expectedRedirectUri.port ||
      redirectUri.pathname !== expectedRedirectUri.pathname ||
      redirectUri.username !== expectedRedirectUri.username ||
      redirectUri.password !== expectedRedirectUri.password ||
      [...expectedRedirectUri.searchParams].some(
        ([key, value]) => redirectUri.searchParams.get(key) !== value,
      )
    ) {
      throw new Error(
        `Authorization redirect destination does not match the effective PAR redirect URI: ${finalRedirectUri}`,
      );
    }

    return await verifyAuthorizationResponse({
      authorizationResponse: parseAuthorizationResponse(
        redirectUri.searchParams,
      ),
      iss: options.baseUrl,
      state: this.requireParState(options.state),
    });
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

  private requireParState(state: string | undefined): string {
    if (!state) {
      throw new Error("OAuth state from PAR is missing");
    }

    return state;
  }
}

function isTruthyEnv(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  const normalized = value.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes";
}

async function clickAndWaitForNavigation(
  page: {
    waitForNavigation: (options: {
      waitUntil: "domcontentloaded";
    }) => Promise<unknown>;
    evaluate: (
      fn: (el: Element) => void,
      el: unknown,
    ) => Promise<unknown>;
  },
  element: unknown,
): Promise<void> {
  await Promise.all([
    page.waitForNavigation({ waitUntil: "domcontentloaded" }).catch(() => undefined),
    // DOM click avoids Puppeteer "not clickable" on covered/hidden nodes.
    page.evaluate((el) => {
      (el as HTMLElement).click();
    }, element),
  ]);
}

async function completeAuthorizeHeadless(
  authorizeUrl: string,
  log: { debug: (...args: unknown[]) => void; info: (...args: unknown[]) => void },
): Promise<void> {
  const username = process.env.CONFIG_IDP_USERNAME || "user";
  const password = process.env.CONFIG_IDP_PASSWORD || "wct-demo";
  const timeoutMs = Number(process.env.CONFIG_AUTHORIZE_HEADLESS_TIMEOUT_MS || "120000");

  const puppeteer = await import("puppeteer");
  const executablePath =
    process.env.PUPPETEER_EXECUTABLE_PATH ||
    process.env.CHROME_PATH ||
    undefined;
  const browser = await puppeteer.default.launch({
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--ignore-certificate-errors",
      "--disable-dev-shm-usage",
    ],
    ...(executablePath ? { executablePath } : {}),
    headless: true,
    ignoreHTTPSErrors: true,
  });

  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(timeoutMs);
    await page.goto(authorizeUrl, { waitUntil: "domcontentloaded" });

    const deadline = Date.now() + timeoutMs;
    let lastActionAt = 0;
    while (Date.now() < deadline) {
      const currentUrl = page.url();
      log.debug(`Headless authorize at: ${currentUrl}`);

      if (
        currentUrl.startsWith("http://localhost:") ||
        currentUrl.startsWith("http://127.0.0.1:")
      ) {
        log.info("Headless authorize reached local callback URL");
        return;
      }

      const usernameSelector =
        'input#id_username, input[name="username"], input[type="text"]';
      const passwordSelector =
        'input#id_password, input[name="password"], input[type="password"]';
      const usernameInput = await page.$(usernameSelector);
      const passwordInput = await page.$(passwordSelector);
      if (usernameInput && passwordInput) {
        await page.evaluate(
          (userSel, passSel, user, pass) => {
            const userEl = document.querySelector(userSel) as HTMLInputElement | null;
            const passEl = document.querySelector(passSel) as HTMLInputElement | null;
            if (!userEl || !passEl) {
              return;
            }
            userEl.focus();
            userEl.value = user;
            userEl.dispatchEvent(new Event("input", { bubbles: true }));
            passEl.focus();
            passEl.value = pass;
            passEl.dispatchEvent(new Event("input", { bubbles: true }));
          },
          usernameSelector,
          passwordSelector,
          username,
          password,
        );
        const submit =
          (await page.$('button#submit, button[type="submit"], input[type="submit"]')) ??
          null;
        if (submit) {
          await clickAndWaitForNavigation(page, submit);
        } else {
          await page.keyboard.press("Enter");
          await page.waitForNavigation({ waitUntil: "domcontentloaded" }).catch(() => undefined);
        }
        lastActionAt = Date.now();
        continue;
      }

      const consent = await page.$(
        'button#confirm, button[name="confirm"], button#agree, a#confirm, button[name="confirm_access"]',
      );
      if (consent) {
        await clickAndWaitForNavigation(page, consent);
        lastActionAt = Date.now();
        continue;
      }

      // Prefer the demo CIE OIDC IdP over production CIE SAML2 (both may appear
      // in the SATOSA disco dropdown as anchors whose href contains "cie").
      const cieOidcLink = await page.$('a[href*="cie-provider.example.org"]');
      if (cieOidcLink) {
        const href = await page.evaluate(
          (el) => (el as HTMLAnchorElement).href,
          cieOidcLink,
        );
        log.info(`Headless authorize selecting CIE OIDC: ${href}`);
        await Promise.all([
          page.waitForNavigation({ waitUntil: "domcontentloaded" }).catch(() => undefined),
          page.goto(href, { waitUntil: "domcontentloaded" }),
        ]);
        lastActionAt = Date.now();
        continue;
      }

      const cieButton = await page.$("button.eid-card-btn-cie");
      if (cieButton) {
        log.info("Headless authorize opening CIE card");
        await clickAndWaitForNavigation(page, cieButton);
        lastActionAt = Date.now();
        continue;
      }

      // Avoid busy-looping the same idle page: wait for disco cards if present.
      if (Date.now() - lastActionAt > 2000) {
        await page
          .waitForSelector(
            'button.eid-card-btn-cie, a[href*="cie-provider.example.org"], input#id_username, input#id_password',
            { timeout: 2000 },
          )
          .catch(() => undefined);
        lastActionAt = Date.now();
      } else {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    throw new Error(
      `Headless authorize timed out after ${timeoutMs}ms at ${page.url()}`,
    );
  } finally {
    await browser.close();
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
