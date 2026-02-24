import { CreateAuthorizationResponseResult } from "@pagopa/io-wallet-oid4vp";

import { StepFlow, type StepResponse } from "@/step/step-flow";

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

  async run(_: RedirectUriOptions): Promise<RedirectUriStepResponse> {
    this.log.warn("Method not implemented.");
    return { success: false };
  }
}
