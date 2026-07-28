import {
  CreateAuthorizationResponseResult,
  fetchAuthorizationResponse,
} from "@pagopa/io-wallet-oid4vp";

import { fetchWithConfig, uriMatchesDeclaredBasePaths } from "@/logic";
import { StepFlow, type StepResponse } from "@/step/step-flow";

export type RedirectUriExecuteStepResponse = RedirectUriHttpResponseMetadata &
  (
    | {
        redirectUri: undefined;
        redirectUriAttested: undefined;
        responseCode: undefined;
      }
    | {
        redirectUri: URL;
        /**
         * Whether the returned `redirect_uri` matches one of the base paths attested
         * in the verifier's `redirect_uris` metadata. `undefined` when the verifier
         * declares no `redirect_uris`, i.e. the requirement could not be verified.
         */
        redirectUriAttested: boolean | undefined;
        responseCode: string;
      }
  );

export interface RedirectUriOptions {
  /**
   * Base paths attested in the verifier's `redirect_uris` metadata, obtained from its
   * Trust Chain. When omitted, the returned `redirect_uri` cannot be validated.
   */
  allowedRedirectUris?: string[];
  authorizationResponse: CreateAuthorizationResponseResult;
  responseUri: string;
}

export type RedirectUriStepResponse = StepResponse & {
  response?: RedirectUriExecuteStepResponse;
};

interface RedirectUriHttpResponseMetadata {
  contentType: string | undefined;
  status: number | undefined;
}

/**
 * Implementation of the Redirect URI Step for OpenID4VP flow.
 * This step handles processing the redirect URI after the authorization response.
 */
export class RedirectUriDefaultStep extends StepFlow {
  static readonly tag = "REDIRECT_URI";

  async run(options: RedirectUriOptions): Promise<RedirectUriStepResponse> {
    const log = this.log;
    log.debug("Starting redirect uri step...");

    return this.execute<RedirectUriExecuteStepResponse>(async () => {
      if (!options.authorizationResponse.jarm) {
        throw new Error(
          "JARM response is missing in the authorization response",
        );
      }

      let contentType: string | undefined;
      let status: number | undefined;

      const fetchCallback = fetchWithConfig(this.config.network, {
        onResponse: (response) => {
          contentType = response.headers.get("content-type") ?? undefined;
          status = response.status;
        },
      });

      log.info(`Fetching authorization response from: ${options.responseUri}`);
      const { redirect_uri } = await fetchAuthorizationResponse({
        authorizationResponseJarm:
          options.authorizationResponse.jarm.responseJwe,
        callbacks: {
          fetch: fetchCallback,
        },
        presentationResponseUri: options.responseUri,
      });

      log.debug("Fetched redirect_uri:", redirect_uri);

      if (!redirect_uri) {
        return {
          contentType,
          redirectUri: undefined,
          redirectUriAttested: undefined,
          responseCode: undefined,
          status,
        };
      }

      const redirectUri = new URL(redirect_uri);
      const redirectUriAttested = this.checkRedirectUriIsAttested(
        redirect_uri,
        options.allowedRedirectUris,
      );

      const responseCode = redirectUri.searchParams.get("response_code");
      log.debug("Extracted response_code:", responseCode);
      if (!responseCode) {
        throw new Error("Response code is missing in the redirect URI");
      }

      // An unattested redirect target must not be followed: the wallet cannot tell it
      // apart from an endpoint mix-up attack.
      if (redirectUriAttested !== false) {
        await fetch(redirectUri).catch((e) => {
          log.debug(
            `Error fetching redirect_uri endpoint at ${redirectUri}. Details: ${JSON.stringify(e)}`,
          );
        });
      }

      return {
        contentType,
        redirectUri,
        redirectUriAttested,
        responseCode,
        status,
      };
    });
  }

  tag(): string {
    return RedirectUriDefaultStep.tag;
  }

  /**
   * Checks the returned `redirect_uri` against the base paths attested in the verifier's
   * `redirect_uris` metadata, as required to prevent endpoint mix-up attacks.
   * @returns `true` on a match, `false` on a mismatch, `undefined` when the verifier
   * attests no `redirect_uris` and the requirement therefore cannot be verified.
   */
  private checkRedirectUriIsAttested(
    redirectUri: string,
    allowedRedirectUris: string[] | undefined,
  ): boolean | undefined {
    const log = this.log;

    if (!allowedRedirectUris || allowedRedirectUris.length === 0) {
      log.warn(
        "Verifier metadata attests no redirect_uris: cannot verify that the returned redirect_uri belongs to the Relying Party. Skipping the check.",
      );
      return undefined;
    }

    log.debug(
      `Validating redirect_uri against ${allowedRedirectUris.length} attested redirect_uris: ${allowedRedirectUris.join(", ")}`,
    );

    if (!uriMatchesDeclaredBasePaths(redirectUri, allowedRedirectUris)) {
      log.error(
        `Redirect URI "${redirectUri}" does not match any redirect_uri attested in the verifier's metadata (${allowedRedirectUris.join(", ")}). Not following the redirect.`,
      );
      return false;
    }

    log.debug("redirect_uri matches an attested redirect_uri");
    return true;
  }
}
