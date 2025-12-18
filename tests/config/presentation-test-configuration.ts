import { FetchMetadataDefaultStep, FetchMetadataOptions } from "@/step";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestOptions,
} from "@/step/presentation/authorization-request-step";

import { TestConfiguration } from "./test-registry";

interface PresentationTestConfigurationOptions {
  authorize?: {
    options?: AuthorizationRequestOptions;
    stepClass: typeof AuthorizationRequestDefaultStep;
  };
  fetchMetadata?: {
    options?: FetchMetadataOptions;
    stepClass: typeof FetchMetadataDefaultStep;
  };
  name: string;
}

/**
 * Configuration class for Presentation conformance tests
 */
export class PresentationTestConfiguration implements TestConfiguration {
  public readonly authorize?: PresentationTestConfigurationOptions["authorize"];
  public readonly fetchMetadata?: PresentationTestConfigurationOptions["fetchMetadata"];
  public readonly name: string;

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
    });
  }
}
