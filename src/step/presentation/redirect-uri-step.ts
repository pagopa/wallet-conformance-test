import { CreateOpenid4vpAuthorizationResponseResult } from "@pagopa/io-wallet-oid4vp";

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

/**
 * Implementation of the Redirect URI Step for OpenID4VP flow.
 * This step handles processing the redirect URI after the authorization response.
 */
export class RedirectUriDefaultStep extends StepFlow {
  tag = "REDIRECT URI";

  async run(_: RedirectUriOptions): Promise<RedirectUriStepResult> {
    this.log.warn("Method not implemented.");
    return { success: false };
  }
}
