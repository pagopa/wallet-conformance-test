import { CreateAuthorizationResponseResult, fetchAuthorizationResponse } from "@pagopa/io-wallet-oid4vp";

import { StepFlow, type StepResponse } from "@/step/step-flow";
import { partialCallbacks } from "@/logic";

export type RedirectUriExecuteStepResponse =
  | {
      redirectUri: undefined;
      responseCode: undefined;
    }
  | {
      redirectUri: URL;
      responseCode: string;
    };

export interface RedirectUriOptions {
  authorizationResponse: CreateAuthorizationResponseResult;
  responseUri: string;
}

export type RedirectUriStepResponse = StepResponse & {
  response?: RedirectUriExecuteStepResponse;
};

/**
 * Implementation of the Redirect URI Step for OpenID4VP flow.
 * This step handles processing the redirect URI after the authorization response.
 */
export class RedirectUriDefaultStep extends StepFlow {
  tag = "REDIRECT URI";

  async run(options: RedirectUriOptions): Promise<RedirectUriStepResponse> {
    const log = this.log.withTag(this.tag);
    log.info("Starting redirect uri step...");

    return this.execute<RedirectUriExecuteStepResponse>(async () => {
      if (!options.authorizationResponse.jarm) {
        throw new Error(
          "JARM response is missing in the authorization response",
        );
      }

      log.info(`Fetching authorization response from: ${options.responseUri}`);
      const { redirect_uri } = await fetchAuthorizationResponse({
        authorizationResponseJarm:
          options.authorizationResponse.jarm.responseJwe,
        callbacks: {
          ...partialCallbacks.fetch,
        },
        presentationResponseUri: options.responseUri,
      });

      if (!redirect_uri) {
        return {
          redirectUri: undefined,
          responseCode: undefined,
        };
      }

      const redirectUri = new URL(redirect_uri);
      const responseCode = redirectUri.searchParams.get("response_code");
      if (!responseCode) {
        throw new Error("Response code is missing in the redirect URI");
      }

      return {
        redirectUri,
        responseCode,
      };
    });
  }

}
