import type { AuthorizationResponse } from "@pagopa/io-wallet-oid4vci";
import type { ParsedAuthorizeRequestResult } from "@pagopa/io-wallet-oid4vp";

import { fetchWithConfig } from "@/logic";
import { mintHighIdToken } from "@/logic/pid-mrtd/mock-idp";
import { StepFlow, StepResponse } from "@/step/step-flow";
import { PidIdentityConfig } from "@/types/pid-issuance";

export interface MockEidLoaInjectionAuthStepOptions {
  /**
   * Authorization endpoint URL (from issuer metadata `authorization_endpoint`)
   */
  authorizationEndpoint: string;

  /**
   * Issuer base URL — used as `iss` fallback and as `aud` for the mock ID Token
   */
  baseUrl: string;

  /**
   * wallet client_id (public key kid from wallet attestation)
   */
  clientId: string;

  /**
   * Mock identity attributes from `[issuance_pid]` config section
   */
  identity: PidIdentityConfig;

  /**
   * `request_uri` obtained from the PAR step
   */
  requestUri: string;
}

export interface MockEidLoaInjectionAuthExecuteResponse {
  authorizeResponse: AuthorizationResponse;
  iss: string;
  requestObject?: ParsedAuthorizeRequestResult["payload"];
  requestObjectJwt: string;
}

export type MockEidLoaInjectionAuthStepResponse = StepResponse & {
  response?: MockEidLoaInjectionAuthExecuteResponse;
};

/**
 * Step 3a — Mock eID LoA Injection (L3 / CIE+PIN).
 *
 * Bypasses the real CIE+PIN authentication by:
 * 1. Calling the AS authorization endpoint with `redirect: "manual"` to
 *    capture the 302 redirect to the CIE IdP without following it.
 * 2. Extracting the AS eID callback URL from the `redirect_uri` param in the
 *    Location header of that redirect.
 * 3. Minting a synthetic CIE+PIN ID Token via {@link mintHighIdToken}.
 * 4. POSTing the token to the AS eID callback URL (form-encoded body).
 * 5. Following the callback's 302 redirect to retrieve the `code` from the
 *    wallet redirect_uri.
 *
 * The PID Provider SUT must be running in test mode (mock_mrtd_enabled) that
 * accepts unsigned/ephemeral keys and skips real CIE hardware verification.
 */
export class MockEidLoaInjectionAuthDefaultStep extends StepFlow {
  static readonly tag = "MOCK_EID_LOA_INJECTION";

  async run(
    options: MockEidLoaInjectionAuthStepOptions,
  ): Promise<MockEidLoaInjectionAuthStepResponse> {
    return this.execute<MockEidLoaInjectionAuthExecuteResponse>(async () => {
      const log = this.log;
      const fetchFn = fetchWithConfig(this.config.network);

      log.debug("Starting MockEidLoaInjectionAuth Step (L3/CIE+PIN)");

      const authorizeUrl = `${options.authorizationEndpoint}?client_id=${encodeURIComponent(options.clientId)}&request_uri=${encodeURIComponent(options.requestUri)}`;

      log.info(`Calling authorization endpoint: ${authorizeUrl}`);
      const authorizeRedirectResponse = await fetchFn(authorizeUrl, {
        redirect: "manual",
      });

      if (
        authorizeRedirectResponse.status !== 302 &&
        authorizeRedirectResponse.status !== 301 &&
        authorizeRedirectResponse.status !== 303
      ) {
        throw new Error(
          `Expected a redirect (301/302/303) from authorization endpoint but got HTTP ${authorizeRedirectResponse.status}`,
        );
      }

      const idpRedirectUrl = authorizeRedirectResponse.headers.get("location");
      if (!idpRedirectUrl) {
        throw new Error(
          "Authorization endpoint redirect did not include a Location header",
        );
      }

      log.debug(`Authorization endpoint redirected to IdP: ${idpRedirectUrl}`);

      let parsedIdpUrl: URL;
      try {
        parsedIdpUrl = new URL(idpRedirectUrl);
      } catch {
        throw new Error(
          `Authorization endpoint returned an invalid redirect URL: ${idpRedirectUrl}`,
        );
      }

      const asCallbackUrl = parsedIdpUrl.searchParams.get("redirect_uri");
      if (!asCallbackUrl) {
        throw new Error(
          `IdP redirect URL does not contain 'redirect_uri' parameter. URL: ${idpRedirectUrl}`,
        );
      }

      const state = parsedIdpUrl.searchParams.get("state") ?? undefined;
      log.debug(`AS eID callback URL: ${asCallbackUrl}`);
      log.debug(`Authorization state: ${state ?? "(none)"}`);

      log.info("Minting mock CIE+PIN (LoA High) ID Token...");
      const { idToken } = await mintHighIdToken(
        options.identity,
        options.baseUrl,
        options.baseUrl,
        state,
      );
      log.debug("Mock ID Token minted successfully");

      const formBody = new URLSearchParams();
      formBody.set("id_token", idToken);
      if (state) {
        formBody.set("state", state);
      }

      log.info(`POSTing mock ID Token to AS callback: ${asCallbackUrl}`);
      const callbackResponse = await fetchFn(asCallbackUrl, {
        body: formBody.toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
        redirect: "manual",
      });

      log.debug(`AS callback responded with HTTP ${callbackResponse.status}`);

      let codeLocation = callbackResponse.headers.get("location");

      if (
        !codeLocation &&
        (callbackResponse.status === 200 || callbackResponse.status === 302)
      ) {
        const body = await callbackResponse.text();
        log.debug(`AS callback body: ${body}`);
      }

      if (
        (callbackResponse.status === 301 ||
          callbackResponse.status === 302 ||
          callbackResponse.status === 303) &&
        codeLocation
      ) {
        log.debug(`Following callback redirect to: ${codeLocation}`);
        const finalResponse = await fetchFn(codeLocation, {
          redirect: "manual",
        });
        const finalLocation = finalResponse.headers.get("location");
        if (finalLocation) {
          codeLocation = finalLocation;
        }
      }

      if (!codeLocation) {
        throw new Error(
          `AS eID callback did not return a redirect with authorization code. HTTP status: ${callbackResponse.status}`,
        );
      }

      let parsedCodeUrl: URL;
      try {
        parsedCodeUrl = new URL(codeLocation);
      } catch {
        parsedCodeUrl = new URL(codeLocation, options.baseUrl);
      }

      const code = parsedCodeUrl.searchParams.get("code");
      if (!code) {
        throw new Error(
          `Final redirect URL does not contain 'code' parameter. URL: ${codeLocation}`,
        );
      }

      const responseIss = parsedCodeUrl.searchParams.get("iss");
      const responseState = parsedCodeUrl.searchParams.get("state");

      log.info("Authorization code obtained successfully");

      const authorizeResponse: AuthorizationResponse = {
        code,
        iss: responseIss ?? options.baseUrl,
        state: responseState ?? state ?? "",
      };

      const syntheticRequestObject = state
        ? ({ state } as ParsedAuthorizeRequestResult["payload"])
        : undefined;

      return {
        authorizeResponse,
        iss: options.baseUrl,
        requestObject: syntheticRequestObject,
        requestObjectJwt: idToken,
      };
    });
  }

  tag(): string {
    return MockEidLoaInjectionAuthDefaultStep.tag;
  }
}
