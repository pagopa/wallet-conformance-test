import { FetchMetadataDefaultStep, FetchMetadataOptions } from "@/step";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestOptions,
} from "@/step/presentation/authorization-request-step";
import { RedirectUriDefaultStep } from "@/step/presentation/redirect-uri-step";

import { TestConfiguration } from "./test-registry";

interface PresentationTestConfigurationOptions {
  authorize?: {
    options?: Partial<AuthorizationRequestOptions>;
    stepClass: typeof AuthorizationRequestDefaultStep;
  };
  fetchMetadata?: {
    options?: Partial<FetchMetadataOptions>;
    stepClass: typeof FetchMetadataDefaultStep;
  };
  name: string;
  redirectUri?: {
    stepClass: typeof RedirectUriDefaultStep;
  };
}

/**
 * Configuration class for Presentation conformance tests
 */
export class PresentationTestConfiguration implements TestConfiguration {
  public readonly authorize: PresentationTestConfigurationOptions["authorize"];
  public readonly fetchMetadata: PresentationTestConfigurationOptions["fetchMetadata"];
  public readonly name: string;
  public readonly redirectUri: PresentationTestConfigurationOptions["redirectUri"];

  constructor(config: PresentationTestConfigurationOptions) {
    this.name = config.name;

    this.fetchMetadata = {
      options: config.fetchMetadata?.options,
      stepClass: config.fetchMetadata?.stepClass ?? FetchMetadataDefaultStep,
    };

    this.authorize = {
      options: config.authorize?.options,
      stepClass: config.authorize?.stepClass ?? AuthorizationRequestDefaultStep,
    };

    this.redirectUri = {
      stepClass: config.redirectUri?.stepClass ?? RedirectUriDefaultStep,
    };
  }

  static createCustom(
    config: ConstructorParameters<typeof PresentationTestConfiguration>[0],
  ) {
    return new PresentationTestConfiguration(config);
  }

  static createDefault(): PresentationTestConfiguration {
    return new PresentationTestConfiguration({
      authorize: {
        stepClass: AuthorizationRequestDefaultStep,
      },
      fetchMetadata: {
        stepClass: FetchMetadataDefaultStep,
      },
      name: "Presentation Happy Flow",
      redirectUri: {
        stepClass: RedirectUriDefaultStep,
      },
    });
  }
}
