import {
  CreateOpenid4vpAuthorizationResponseResult,
  fetchAuthorizationResponse,
} from "@pagopa/io-wallet-oid4vp";

import { partialCallbacks } from "@/logic";
import { StepFlow, type StepResult } from "@/step/step-flow";

export interface RedirectUriOptions {
  authorizationResponse: CreateOpenid4vpAuthorizationResponseResult;
  responseUri: string;
}

export type RedirectUriStepResponse =
  | {
      redirectUri: undefined;
      responseCode: undefined;
    }
  | {
      redirectUri: URL;
      responseCode: string;
    };

export type RedirectUriStepResult = StepResult & {
  response?: RedirectUriStepResponse;
};

export class RedirectUriDefaultStep extends StepFlow {
  tag = "REDIRECT URI";

  async run(options: RedirectUriOptions): Promise<RedirectUriStepResult> {
    const log = this.log.withTag(this.tag);
    log.info("Starting redirect uri step...");

    return this.execute<RedirectUriStepResponse>(async () => {
      if (!options.authorizationResponse.jarm) {
        throw new Error(
          "JARM response is missing in the authorization response",
        );
      }

      log.info(
        `Fetching authorization response from: ${options.responseUri}`,
      );
      const { redirect_uri } = await fetchAuthorizationResponse({
        authorizationResponseJarm:
          options.authorizationResponse.jarm.responseJwt,
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
