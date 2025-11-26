import {
  FetchMetadataDefaultStep,
  FetchMetadataOptions,
} from "@/step/fetch-metadata-step";

import { TestConfiguration } from "./test-registry";

interface PresentationTestConfigurationOptions {
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
  public readonly fetchMetadata?: PresentationTestConfigurationOptions["fetchMetadata"];
  public readonly name: string;

  constructor(config: PresentationTestConfigurationOptions) {
    this.name = config.name;
    this.fetchMetadata = {
      options: config.fetchMetadata?.options,
      stepClass: config.fetchMetadata?.stepClass ?? FetchMetadataDefaultStep,
    };
  }

  static createCustom(
    config: ConstructorParameters<typeof PresentationTestConfiguration>[0],
  ) {
    return new PresentationTestConfiguration(config);
  }

  static createDefault(): PresentationTestConfiguration {
    return new PresentationTestConfiguration({
      fetchMetadata: {
        stepClass: FetchMetadataDefaultStep,
      },
      name: "Presentation Happy Flow",
    });
  }
}
