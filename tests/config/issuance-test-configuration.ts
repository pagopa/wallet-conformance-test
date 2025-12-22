import { FetchMetadataDefaultStep, FetchMetadataOptions } from "@/step";
import {
  AuthorizeDefaultStep,
  AuthorizeStepOptions,
  CredentialRequestDefaultStep,
  CredentialRequestStepOptions,
  NonceRequestDefaultStep,
  NonceRequestStepOptions,
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestOptions,
  TokenRequestDefaultStep,
  TokenRequestStepOptions,
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

  public readonly credentialRequest?: {
    options?: CredentialRequestStepOptions;
    stepClass: typeof CredentialRequestDefaultStep;
  };
  public readonly fetchMetadata?: {
    options?: FetchMetadataOptions;
    stepClass: typeof FetchMetadataDefaultStep;
  };
  public readonly name: string;
  public readonly nonceRequest?: {
    options?: NonceRequestStepOptions;
    stepClass: typeof NonceRequestDefaultStep;
  };
  public readonly pushedAuthorizationRequest?: {
    options?: PushedAuthorizationRequestOptions;
    stepClass: typeof PushedAuthorizationRequestDefaultStep;
  };
  public readonly tokenRequest?: {
    options?: TokenRequestStepOptions;
    stepClass: typeof TokenRequestDefaultStep;
  };

  constructor(config: {
    authorize?: {
      options?: AuthorizeStepOptions;
      stepClass: typeof AuthorizeDefaultStep;
    };
    credentialConfigurationId: string;
    credentialRequest?: {
      options?: CredentialRequestStepOptions;
      stepClass: typeof CredentialRequestDefaultStep;
    };
    fetchMetadata?: {
      options?: FetchMetadataOptions;
      stepClass?: typeof FetchMetadataDefaultStep;
    };
    name: string;
    nonceRequest?: {
      options?: NonceRequestStepOptions;
      stepClass: typeof NonceRequestDefaultStep;
    };
    pushedAuthorizationRequest?: {
      options?: PushedAuthorizationRequestOptions;
      stepClass?: typeof PushedAuthorizationRequestDefaultStep;
    };
    tokenRequest?: {
      options?: TokenRequestStepOptions;
      stepClass: typeof TokenRequestDefaultStep;
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
    this.credentialRequest = {
      options: config.credentialRequest?.options,
      stepClass:
        config.credentialRequest?.stepClass ?? CredentialRequestDefaultStep,
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
      credentialRequest: {
        stepClass: CredentialRequestDefaultStep,
      },
      fetchMetadata: {
        stepClass: FetchMetadataDefaultStep,
      },
      name: "Issuance Happy Flow",
      nonceRequest: {
        stepClass: NonceRequestDefaultStep,
      },
      pushedAuthorizationRequest: {
        stepClass: PushedAuthorizationRequestDefaultStep,
      },
      tokenRequest: {
        stepClass: TokenRequestDefaultStep,
      },
    });
  }
}
