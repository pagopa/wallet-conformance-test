import {
  fetchAuthorizationRequest,
  type FetchAuthorizationRequestResult,
} from "@pagopa/io-wallet-oid4vp";

import { verifyJwt } from "@/logic";
import { StepFlow, type StepResult } from "@/step/step-flow";

export interface AuthorizationRequestOptions {
  authorizeRequestUrl: string;
}

export type AuthorizationRequestStepResponse = StepResult & {
  response?: FetchAuthorizationRequestResult;
};

export class AuthorizationRequestStep extends StepFlow {
  tag = "AUTHORIZATION";

  async run(
    options: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResponse> {
    const log = this.log.withTag(this.tag);
    log.info("Starting authorization request step...");

    return this.execute<FetchAuthorizationRequestResult>(async () => {
      const { parsedQrCode, requestObject } = await fetchAuthorizationRequest({
        authorizeRequestUrl: options.authorizeRequestUrl,
        callbacks: { verifyJwt },
      });

      return {
        parsedQrCode,
        requestObject,
      };
    });
  }
}
