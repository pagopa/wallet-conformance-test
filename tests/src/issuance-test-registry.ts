import { IssuerTestConfiguration } from "./issuance-test-configuration";

/**
 * Registry for managing test configurations
 * Provides a centralized way to register and retrieve test configurations
 */
export class IssuerTestRegistry {
  private static instance: IssuerTestRegistry;
  private configurations: Map<string, IssuerTestConfiguration[]> = new Map();

  private constructor() {}

  /**
   * Get the singleton instance of the registry
   */
  static getInstance(): IssuerTestRegistry {
    if (!IssuerTestRegistry.instance) {
      IssuerTestRegistry.instance = new IssuerTestRegistry();
    }
    return IssuerTestRegistry.instance;
  }

  /**
   * Register a test configuration
   * @param flowName - The name of the flow test configuration
   * @param config - The test configuration to register
   * @returns The registry instance for chaining
   */
  register(
    flowName: string,
    config: IssuerTestConfiguration,
  ): IssuerTestRegistry {
    const key = flowName;
    if (this.configurations.has(key)) {
      this.configurations.get(key)?.push(config);
    } else {
      this.configurations.set(key, [config]);
    }
    return this;
  }

  /**
   * Register multiple test configurations at once
   * @param configs - Array of test configurations to register
   * @returns The registry instance for chaining
   */
  registerMany(
    flowName: string,
    configs: IssuerTestConfiguration[],
  ): IssuerTestRegistry {
    configs.forEach((config) => this.register(flowName, config));
    return this;
  }

  /**
   * Get a specific configurations by flow name
   * @param flowName - The name of the flow test configuration to retrieve
   * @returns The test configurations or undefined if not found
   */
  get(flowName: string): IssuerTestConfiguration[] {
    const testConfigurations = this.configurations.get(flowName);
    if (!testConfigurations) {
      const availableFlows = Array.from(this.configurations.keys()).join(", ");
      throw new Error(
        `No test configuration registered for flow "${flowName}"! ` +
          `Available flows: ${availableFlows || "none"}. ` +
          `Please register a configuration using registerTest() or registerTests() before running the tests.`,
      );
    }
    return testConfigurations;
  }

  /**
   * Check if a configuration is registered
   * @param flowName - The name of the flow test configuration to check
   * @returns True if the configuration is registered
   */
  has(testName: string): boolean {
    return this.configurations.has(testName);
  }

  /**
   * Clear all registered configurations
   */
  clear(): void {
    this.configurations.clear();
  }
}

/**
 * Convenience function to get the registry instance
 */
export function getTestRegistry(): IssuerTestRegistry {
  return IssuerTestRegistry.getInstance();
}

/**
 * Convenience function to register a configuration
 * @param config - The test configuration to register
 * @returns The registry instance for chaining
 */
export function registerTest(
  flowName: string,
  config: IssuerTestConfiguration,
): IssuerTestRegistry {
  return IssuerTestRegistry.getInstance().register(flowName, config);
}

/**
 * Convenience function to register multiple configurations
 * @param configs - Array of test configurations to register
 * @returns The registry instance for chaining
 */
export function registerTests(
  flowName: string,
  configs: IssuerTestConfiguration[],
): IssuerTestRegistry {
  return IssuerTestRegistry.getInstance().registerMany(flowName, configs);
}
