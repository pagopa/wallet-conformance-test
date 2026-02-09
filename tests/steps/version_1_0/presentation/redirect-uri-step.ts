import { fetchAuthorizationResponse } from "@pagopa/io-wallet-oid4vp";

import { partialCallbacks } from "@/logic";
import {
  RedirectUriDefaultStep,
  RedirectUriOptions,
  RedirectUriStepResponse,
  RedirectUriStepResult,
} from "@/step/presentation/redirect-uri-step";

export class RedirectUriITWallet1_0Step extends RedirectUriDefaultStep {
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

      log.info(`Fetching authorization response from: ${options.responseUri}`);
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
