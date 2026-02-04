/**
 * Test Metadata Helpers
 *
 * Provides minimal metadata definition and auto-registration for test specs.
 * Custom steps and options are auto-discovered from the test directory,
 * so they don't need to be declared in metadata.
 *
 * Test configurations are automatically registered when defineIssuanceTest
 * or definePresentationTest is called at module load time.
 */

import path from "path";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { createLogger } from "@/logic/logs";

import { IssuerTestConfiguration } from "./issuance-test-configuration";
import { PresentationTestConfiguration } from "./presentation-test-configuration";
import { testLoader } from "./test-loader";

const log = createLogger().withTag("test-metadata");

/**
 * Helper to define and auto-register issuance test
 * Registers test configuration when called at module load time
 * Auto-discovers custom steps and options from the caller's directory
 * @param name Unique test name (used for registry lookup and display)
 */
export async function defineIssuanceTest(
  name: string,
): Promise<IssuerTestConfiguration[]> {
  try {
    // Get caller's directory to scan for custom steps/options
    const callerDir = getCallerDirectory();

    const config = loadConfigWithHierarchy();

    // Auto-discover custom steps and options from caller's directory
    const customSteps = await testLoader.discoverCustomSteps(callerDir);
    const stepOptions = await testLoader.discoverStepOptions(
      callerDir,
      customSteps,
    );

    // Get credential types to test
    const credentialTypes = config.issuance.credential_types;

    // Validate credential types configuration
    validateCredentialTypes(credentialTypes);

    // Register a test configuration for each credential type
    const testConfig = credentialTypes.map((credentialType) =>
      IssuerTestConfiguration.createCustom({
        authorize:
          customSteps.authorize || stepOptions.authorize
            ? {
                options: stepOptions.authorize as any,
                stepClass: customSteps.authorize as any,
              }
            : undefined,
        credentialConfigurationId: credentialType,

        credentialRequest:
          customSteps.credentialRequest || stepOptions.credentialRequest
            ? {
                options: stepOptions.credentialRequest as any,
                stepClass: customSteps.credentialRequest as any,
              }
            : undefined,

        fetchMetadata:
          customSteps.fetchMetadata || stepOptions.fetchMetadata
            ? {
                options: stepOptions.fetchMetadata as any,
                stepClass: customSteps.fetchMetadata as any,
              }
            : undefined,

        name: `${name} - ${credentialType}`,

        nonceRequest:
          customSteps.nonceRequest || stepOptions.nonceRequest
            ? {
                options: stepOptions.nonceRequest as any,
                stepClass: customSteps.nonceRequest as any,
              }
            : undefined,

        pushedAuthorizationRequest:
          customSteps.pushedAuthorizationRequest ||
          stepOptions.pushedAuthorizationRequest
            ? {
                options: stepOptions.pushedAuthorizationRequest as any,
                stepClass: customSteps.pushedAuthorizationRequest as any,
              }
            : undefined,

        tokenRequest:
          customSteps.tokenRequest || stepOptions.tokenRequest
            ? {
                options: stepOptions.tokenRequest as any,
                stepClass: customSteps.tokenRequest as any,
              }
            : undefined,
      }),
    );

    return testConfig;
  } catch (error) {
    log.error(`Error auto-registering test ${name}:`, error);
    throw error;
  }
}

/**
 * Helper to define and auto-register presentation test
 * Registers test configuration when called at module load time
 * Auto-discovers custom steps and options from the caller's directory
 * @param name Unique test name (used for registry lookup and display)
 */
export async function definePresentationTest(
  name: string,
): Promise<PresentationTestConfiguration> {
  // Get caller's directory to scan for custom steps/options
  try {
    const callerDir = getCallerDirectory();

    // Auto-discover custom steps and options from caller's directory
    const customSteps = await testLoader.discoverCustomSteps(callerDir);
    const stepOptions = await testLoader.discoverStepOptions(
      callerDir,
      customSteps,
    );

    // Note: AuthorizationRequestDefaultStep is discovered as "authorizationRequest"
    // but PresentationTestConfiguration expects "authorize" key.
    // This mapping is intentional - see STEP_CLASS_TO_KEY documentation in test-loader.ts
    const testConfig = PresentationTestConfiguration.createCustom({
      authorize:
        customSteps.authorizationRequest || stepOptions.authorizationRequest
          ? {
              options: stepOptions.authorizationRequest as any,
              stepClass: customSteps.authorizationRequest as any,
            }
          : undefined,

      name: name,

      redirectUri: customSteps.redirectUri
        ? {
            stepClass: customSteps.redirectUri as any,
          }
        : undefined,
    });

    return testConfig;
  } catch (error) {
    log.error(`Error auto-registering test ${name}:`, error);
    throw error;
  }
}

/**
 * Detects the caller's directory using stack trace inspection
 * Tries multiple stack depths to handle different transpilers/bundlers
 * @returns Absolute path to the caller's directory
 */
function getCallerDirectory(): string {
  try {
    const error = new Error();
    const stack = error.stack?.split("\n") || [];

    // Try multiple stack depths (transpilers, bundlers might change depth)
    // Skip 0 (Error), 1 (this function), start from 2 (actual caller)
    for (let i = 2; i < Math.min(stack.length, 10); i++) {
      const line = stack[i];
      // Match both formats: (path:line:col) and at path:line:col
      const match =
        line?.match(/\((.+):\d+:\d+\)/) || line?.match(/at (.+):\d+:\d+/);

      if (match?.[1]) {
        const filePath = match[1];
        // Skip node_modules, internal Node.js paths, and this file
        if (
          !filePath.includes("node_modules") &&
          !filePath.startsWith("node:") &&
          !filePath.includes("test-metadata")
        ) {
          const directory = path.dirname(filePath);
          log.info(`Detected caller directory: ${directory}`);
          return directory;
        }
      }
    }

    log.warn("Could not detect caller directory from stack trace, using cwd");
  } catch (error) {
    log.warn(
      `Failed to detect caller directory: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Safe fallback
  return process.cwd();
}

/**
 * Validates credential types configuration
 * @param credentialTypes Array of credential types to validate
 * @throws Error if validation fails
 */
function validateCredentialTypes(
  credentialTypes: unknown,
): asserts credentialTypes is string[] {
  if (!Array.isArray(credentialTypes)) {
    throw new Error(
      `credential_types must be an array. Please set credential_types[] in config.ini [issuance] section.`,
    );
  }

  if (credentialTypes.length === 0) {
    throw new Error(
      `No credential types configured. Please set credential_types[] in config.ini [issuance] section.`,
    );
  }

  // Validate each credential type is a non-empty string
  const invalidTypes = credentialTypes.filter(
    (type) => typeof type !== "string" || type.trim() === "",
  );

  if (invalidTypes.length > 0) {
    throw new Error(
      `Invalid credential types found (must be non-empty strings): ${JSON.stringify(invalidTypes)}`,
    );
  }
}
