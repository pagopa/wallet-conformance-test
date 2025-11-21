import {
  FetchMetadataDefaultStep,
  FetchMetadataOptions,
} from "@/step/issuance/fetch-metadata-step";
import {
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestOptions,
} from "@/step/issuance/pushed-authorization-request-step";

import { TestConfiguration } from "./test-registry";

/**
 * Configuration class for Issuer conformance tests
 */
export class IssuerTestConfiguration implements TestConfiguration {
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

  constructor(config: {
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
  }

  static createCustom(
    config: ConstructorParameters<typeof IssuerTestConfiguration>[0],
  ) {
    return new IssuerTestConfiguration(config);
  }

  static createDefault(): IssuerTestConfiguration {
    return new IssuerTestConfiguration({
      credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
      fetchMetadata: {
        stepClass: FetchMetadataDefaultStep,
      },
      name: "Issuance Happy Flow",
      pushedAuthorizationRequest: {
        stepClass: PushedAuthorizationRequestDefaultStep,
      },
    });
  }
}
