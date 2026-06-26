import {
  CreateAuthorizationResponseResult,
  fetchAuthorizationResponse,
} from "@pagopa/io-wallet-oid4vp";

import { fetchWithConfig } from "@/logic";
import { StepFlow, type StepResponse } from "@/step/step-flow";

export type RedirectUriExecuteStepResponse = RedirectUriHttpResponseMetadata &
  (
    | {
        redirectUri: undefined;
        responseCode: undefined;
      }
    | {
        redirectUri: URL;
        responseCode: string;
      }
  );

export interface RedirectUriOptions {
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

      const configuredFetch = fetchWithConfig(this.config.network);
      let contentType: string | undefined;
      let status: number | undefined;
      const capturingFetch: typeof fetch = async (input, init) => {
        const response = await configuredFetch(input, init);
        contentType = response.headers.get("content-type") ?? undefined;
        status = response.status;
        return response;
      };

      log.info(`Fetching authorization response from: ${options.responseUri}`);
      const { redirect_uri } = await fetchAuthorizationResponse({
        authorizationResponseJarm:
          options.authorizationResponse.jarm.responseJwe,
        callbacks: {
          fetch: capturingFetch,
        },
        presentationResponseUri: options.responseUri,
      });

      log.debug("Fetched redirect_uri:", redirect_uri);

      if (!redirect_uri) {
        return {
          contentType,
          redirectUri: undefined,
          responseCode: undefined,
          status,
        };
      }

      const redirectUri = new URL(redirect_uri);
      const responseCode = redirectUri.searchParams.get("response_code");
      log.debug("Extracted response_code:", responseCode);
      if (!responseCode) {
        throw new Error("Response code is missing in the redirect URI");
      }

      return {
        contentType,
        redirectUri,
        responseCode,
        status,
      };
    });
  }

  tag(): string {
    return RedirectUriDefaultStep.tag;
  }
}
