import { IssuerTestConfiguration } from "./issuance-test-configuration";
import { PresentationTestConfiguration } from "./presentation-test-configuration";

/**
 * Base interface for all test configuration types.
 * Extend this interface to create domain-specific configurations.
 */
export interface TestConfiguration {
  name: string;
}

/**
 * Generic registry for managing test configurations of any type.
 * Provides a centralized and type-safe way to register, retrieve, and manage configurations.
 */
export class TestRegistry<T extends TestConfiguration> {
  private configurations = new Map<string, T[]>();

  /**
   * Clear all registered configurations
   */
  clear(): void {
    this.configurations.clear();
  }

  /**
   * Retrieve configurations for a given flow
   * @param flowName - The name of the flow
   * @returns An array of configurations if found
   * @throws Error if the flow is not registered
   */
  get(flowName: string): T[] {
    const testConfigurations = this.configurations.get(flowName);

    if (!testConfigurations) {
      const availableFlows = Array.from(this.configurations.keys()).join(", ");
      throw new Error(
        `No test configuration registered for flow "${flowName}"! ` +
          `Available flows: ${availableFlows || "none"}. ` +
          `Please register a configuration using registerTest() or registerMany() before running the tests.`,
      );
    }

    return testConfigurations;
  }

  /**
   * Check if a configuration flow is registered
   * @param flowName - The name of the flow to check
   * @returns True if the flow has registered configurations
   */
  has(flowName: string): boolean {
    return this.configurations.has(flowName);
  }

  /**
   * Register multiple test configurations at once
   * @param flowName - The name of the flow
   * @param configs - Array of configurations to register
   * @returns The registry instance for chaining
   */
  registerMany(flowName: string, configs: T[]): this {
    configs.forEach((config) => this.registerTest(flowName, config));
    return this;
  }

  /**
   * Register a single test configuration
   * @param flowName - The name of the flow
   * @param config - The test configuration to register
   * @returns The registry instance for chaining
   */
  registerTest(flowName: string, config: T): this {
    if (this.configurations.has(flowName)) {
      this.configurations.get(flowName)?.push(config);
    } else {
      this.configurations.set(flowName, [config]);
    }
    return this;
  }
}

export const issuerRegistry = new TestRegistry<IssuerTestConfiguration>();
export const presentationRegistry =
  new TestRegistry<PresentationTestConfiguration>();
