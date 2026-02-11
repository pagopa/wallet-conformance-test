import { FetchMetadataDefaultStep } from "@/step";
import { AuthorizationRequestDefaultStep } from "@/step/presentation/authorization-request-step";
import { RedirectUriDefaultStep } from "@/step/presentation/redirect-uri-step";

interface PresentationTestConfigurationOptions {
  authorizeStepClass: typeof AuthorizationRequestDefaultStep;
  fetchMetadataStepClass: typeof FetchMetadataDefaultStep;
  name: string;
  redirectUriStepClass: typeof RedirectUriDefaultStep;
}

/**
 * Configuration class for Presentation conformance tests
 */
export class PresentationTestConfiguration {
  public readonly authorizeStepClass: PresentationTestConfigurationOptions["authorizeStepClass"];
  public readonly fetchMetadataStepClass: PresentationTestConfigurationOptions["fetchMetadataStepClass"];
  public readonly name: string;
  public readonly redirectUriStepClass: PresentationTestConfigurationOptions["redirectUriStepClass"];

  constructor(config: PresentationTestConfigurationOptions) {
    this.name = config.name;
    this.fetchMetadataStepClass =
      config.fetchMetadataStepClass ?? FetchMetadataDefaultStep;
    this.authorizeStepClass =
      config.authorizeStepClass ?? AuthorizationRequestDefaultStep;
    this.redirectUriStepClass =
      config.redirectUriStepClass ?? RedirectUriDefaultStep;
  }

  static createCustom(
    config: ConstructorParameters<typeof PresentationTestConfiguration>[0],
  ) {
    return new PresentationTestConfiguration(config);
  }

  static createDefault(): PresentationTestConfiguration {
    return new PresentationTestConfiguration({
      authorizeStepClass: AuthorizationRequestDefaultStep,
      fetchMetadataStepClass: FetchMetadataDefaultStep,
      name: "Presentation Happy Flow",
      redirectUriStepClass: RedirectUriDefaultStep,
    });
  }
}
