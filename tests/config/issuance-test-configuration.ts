import {
  FetchMetadataOptions,
  FetchMetadataStep,
} from "@/step/issuance/fetch-metadata-step";
import {
  PushedAuthorizationRequestOptions,
  PushedAuthorizationRequestStep,
} from "@/step/issuance/pushed-authorization-request-step";

/**
 * Configuration class for Issuer conformance tests
 */
export class IssuerTestConfiguration {
  public readonly credentialConfigurationId: string;
  public readonly fetchMetadata?: {
    options?: FetchMetadataOptions;
    stepClass: typeof FetchMetadataStep;
  };

  public readonly pushedAuthorizationRequest?: {
    options?: PushedAuthorizationRequestOptions;
    stepClass: typeof PushedAuthorizationRequestStep;
  };

  public readonly testName: string;

  constructor(config: {
    credentialConfigurationId: string;
    fetchMetadata?: {
      options?: FetchMetadataOptions;
      stepClass?: typeof FetchMetadataStep;
    };
    pushedAuthorizationRequest?: {
      options?: PushedAuthorizationRequestOptions;
      stepClass?: typeof PushedAuthorizationRequestStep;
    };
    testName: string;
  }) {
    this.testName = config.testName;
    this.credentialConfigurationId = config.credentialConfigurationId;

    this.fetchMetadata = {
      options: config.fetchMetadata?.options,
      stepClass: config.fetchMetadata?.stepClass ?? FetchMetadataStep,
    };
    this.pushedAuthorizationRequest = {
      options: config.pushedAuthorizationRequest?.options,
      stepClass:
        config.pushedAuthorizationRequest?.stepClass ??
        PushedAuthorizationRequestStep,
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
        stepClass: FetchMetadataStep,
      },
      pushedAuthorizationRequest: {
        stepClass: PushedAuthorizationRequestStep,
      },
      testName: "Issuance Happy Flow",
    });
  }
}
