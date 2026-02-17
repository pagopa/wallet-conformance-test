import { CreatePushedAuthorizationRequestOptions } from "@pagopa/io-wallet-oauth2";

import { createLogger } from "@/logic";
import { PushedAuthorizationRequestDefaultStep } from "@/step/issuance";
import { Config } from "@/types";

export function withParOverrides(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  overrides: Partial<CreatePushedAuthorizationRequestOptions>,
): typeof PushedAuthorizationRequestDefaultStep {
  return class extends StepClass {
    constructor(config: Config, logger: ReturnType<typeof createLogger>) {
      super(config, logger);
      this.parRequestOverrides = overrides;
    }
  } as typeof PushedAuthorizationRequestDefaultStep;
}
