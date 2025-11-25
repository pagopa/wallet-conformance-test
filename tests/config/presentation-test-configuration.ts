import { TestConfiguration } from "./test-registry";

/**
 * Configuration class for Presentation conformance tests
 */
export class PresentationTestConfiguration implements TestConfiguration {
  public readonly name: string;

  constructor(config: { name: string }) {
    this.name = config.name;
  }

  static createCustom(
    config: ConstructorParameters<typeof PresentationTestConfiguration>[0],
  ) {
    return new PresentationTestConfiguration(config);
  }

  static createDefault(): PresentationTestConfiguration {
    return new PresentationTestConfiguration({
      name: "Presentation Happy Flow",
    });
  }
}
