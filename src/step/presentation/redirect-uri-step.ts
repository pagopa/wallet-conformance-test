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

export type RedirectUriStepResponse = StepResult & {
  response?: RedirectUriStepResult;
};

export interface RedirectUriStepResult {
  redirectUri: URL;
  responseCode: string;
}

export class RedirectUriStep extends StepFlow {
  tag = "REDIRECT URI";

  async run(options: RedirectUriOptions): Promise<RedirectUriStepResponse> {
    const log = this.log.withTag(this.tag);
    log.info("Starting redirect uri step...");

    return this.execute<RedirectUriStepResult>(async () => {
      if (!options.authorizationResponse.jarm) {
        throw new Error(
          "JARM response is missing in the authorization response",
        );
      }

      const { redirect_uri } = await fetchAuthorizationResponse({
        authorizationResponseJarm:
          options.authorizationResponse.jarm.responseJwt,
        callbacks: {
          ...partialCallbacks.fetch,
        },
        presentationResponseUri: options.responseUri,
      });

      const redirectUri = new URL(redirect_uri);

      const responseCode = redirectUri.searchParams.get("code");
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
