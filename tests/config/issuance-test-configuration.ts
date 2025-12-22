import { FetchMetadataDefaultStep, FetchMetadataOptions } from "@/step";
import {
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestOptions,
  TokenRequestDefaultStep,
  TokenRequestStepOptions,
  AuthorizeDefaultStep,
  AuthorizeStepOptions,
  NonceRequestDefaultStep,
  NonceRequestStepOptions,
} from "@/step/issuance";

import { TestConfiguration } from "./test-registry";

/**
 * Configuration class for Issuer conformance tests
 */
export class IssuerTestConfiguration implements TestConfiguration {
  public readonly authorize?: {
    options?: AuthorizeStepOptions;
    stepClass: typeof AuthorizeDefaultStep;
  };
  public readonly credentialConfigurationId: string;

  public readonly fetchMetadata?: {
    options?: FetchMetadataOptions;
    stepClass: typeof FetchMetadataDefaultStep;
  };
  public readonly name: string;
  public readonly pushedAuthorizationRequest?: {
    options?: PushedAuthorizationRequestOptions;
    stepClass: typeof PushedAuthorizationRequestDefaultStep;
  };
  public readonly tokenRequest?: {
    options?: TokenRequestStepOptions;
    stepClass: typeof TokenRequestDefaultStep;
  };
  public readonly nonceRequest?: {
    options?: NonceRequestStepOptions;
    stepClass: typeof NonceRequestDefaultStep;
  };

  constructor(config: {
    authorize?: {
      options?: AuthorizeStepOptions;
      stepClass: typeof AuthorizeDefaultStep;
    };
    credentialConfigurationId: string;
    fetchMetadata?: {
      options?: FetchMetadataOptions;
      stepClass?: typeof FetchMetadataDefaultStep;
    };
    name: string;
    pushedAuthorizationRequest?: {
      options?: PushedAuthorizationRequestOptions;
      stepClass?: typeof PushedAuthorizationRequestDefaultStep;
    };
    tokenRequest?: {
      options?: TokenRequestStepOptions;
      stepClass: typeof TokenRequestDefaultStep;
    };
    nonceRequest?: {
      options?: NonceRequestStepOptions;
      stepClass: typeof NonceRequestDefaultStep;
    };
  }) {
    this.name = config.name;
    this.credentialConfigurationId = config.credentialConfigurationId;

    this.fetchMetadata = {
      options: config.fetchMetadata?.options,
      stepClass: config.fetchMetadata?.stepClass ?? FetchMetadataDefaultStep,
    };
    this.pushedAuthorizationRequest = {
      options: config.pushedAuthorizationRequest?.options,
      stepClass:
        config.pushedAuthorizationRequest?.stepClass ??
        PushedAuthorizationRequestDefaultStep,
    };
    this.authorize = {
      options: config.authorize?.options,
      stepClass: config.authorize?.stepClass ?? AuthorizeDefaultStep,
    };
    this.tokenRequest = {
      options: config.tokenRequest?.options,
      stepClass: config.tokenRequest?.stepClass ?? TokenRequestDefaultStep,
    };
    this.nonceRequest = {
      options: config.nonceRequest?.options,
      stepClass: config.nonceRequest?.stepClass ?? NonceRequestDefaultStep,
    };
  }

  static createCustom(
    config: ConstructorParameters<typeof IssuerTestConfiguration>[0],
  ) {
    return new IssuerTestConfiguration(config);
  }

  static createDefault(): IssuerTestConfiguration {
    return new IssuerTestConfiguration({
      authorize: {
        stepClass: AuthorizeDefaultStep,
      },
      credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
      fetchMetadata: {
        stepClass: FetchMetadataDefaultStep,
      },
      name: "Issuance Happy Flow",
      pushedAuthorizationRequest: {
        stepClass: PushedAuthorizationRequestDefaultStep,
      },
      tokenRequest: {
        stepClass: TokenRequestDefaultStep,
      },
      nonceRequest: {
        stepClass: NonceRequestDefaultStep,
      },
    });
  }
}
