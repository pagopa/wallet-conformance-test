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
import { FetchMetadataDefaultStep } from "@/step/fetch-metadata-step";
import {
  PushedAuthorizationRequestDefaultStep,
  TokenRequestDefaultStep,
} from "@/step/issuance";
import { AuthorizeDefaultStep } from "@/step/issuance/authorize-step";
import { CredentialRequestDefaultStep } from "@/step/issuance/credential-request-step";
import { NonceRequestDefaultStep } from "@/step/issuance/nonce-request-step";
import { AuthorizationRequestDefaultStep } from "@/step/presentation/authorization-request-step";
import { RedirectUriDefaultStep } from "@/step/presentation/redirect-uri-step";
import { Config } from "@/types";

import { IssuerTestConfiguration } from "./issuance-test-configuration";
import { PresentationTestConfiguration } from "./presentation-test-configuration";
import { type CustomStepsMap, type StepClass, testLoader } from "./test-loader";

const log = createLogger().withTag("test-metadata");

/**
 * Helper to define and auto-register issuance test
 * Registers test configuration when called at module load time
 * Auto-discovers custom steps from the directory specified in steps_mapping
 * @param name Unique test name (must match a key in config.ini [steps_mapping])
 */
export async function defineIssuanceTest(
  name: string,
): Promise<IssuerTestConfiguration[]> {
  try {
    // Load configuration
    const config = loadConfigWithHierarchy();

    // Resolve primary and fallback directories
    const { fallback, primary } = resolveStepDirectories(name, config);

    // Discover custom steps from primary directory
    let customSteps = await testLoader.discoverCustomSteps(primary);

    // If fallback directory exists and is different, discover and merge steps
    if (fallback) {
      log.info(`Scanning default_steps_dir for missing steps: ${fallback}`);
      const fallbackSteps = await testLoader.discoverCustomSteps(fallback);
      customSteps = mergeStepMaps(customSteps, fallbackSteps);
      log.info(`Merged steps from primary directory and default_steps_dir`);
    }

    // Validate credential types configuration
    validateCredentialTypes(config.issuance.credential_types);

    // Build and return test configurations
    return buildIssuanceTestConfigurations(name, customSteps, config);
  } catch (error) {
    log.error(`Error defining issuance test '${name}':`, error);
    throw error;
  }
}

/**
 * Helper to define and auto-register presentation test
 * Registers test configuration when called at module load time
 * Auto-discovers custom steps from the directory specified in steps_mapping
 * @param name Unique test name (must match a key in config.ini [steps_mapping])
 */
export async function definePresentationTest(
  name: string,
): Promise<PresentationTestConfiguration> {
  try {
    // Load configuration
    const config = loadConfigWithHierarchy();

    // Resolve primary and fallback directories
    const { fallback, primary } = resolveStepDirectories(name, config);

    // Discover custom steps from primary directory
    let customSteps = await testLoader.discoverCustomSteps(primary);

    // If fallback directory exists and is different, discover and merge steps
    if (fallback) {
      log.info(`Scanning default_steps_dir for missing steps: ${fallback}`);
      const fallbackSteps = await testLoader.discoverCustomSteps(fallback);
      customSteps = mergeStepMaps(customSteps, fallbackSteps);
      log.info(`Merged steps from primary directory and default_steps_dir`);
    }

    // Build and return test configuration
    return buildPresentationTestConfiguration(name, customSteps);
  } catch (error) {
    log.error(`Error defining presentation test '${name}':`, error);
    throw error;
  }
}

/**
 * Builds issuance test configurations from custom steps and config.
 * Creates one configuration per credential type.
 *
 * @param flowName The test flow name
 * @param customSteps Discovered custom step classes
 * @param config The loaded configuration
 * @returns Array of test configurations
 */
function buildIssuanceTestConfigurations(
  flowName: string,
  customSteps: CustomStepsMap,
  config: Config,
): IssuerTestConfiguration[] {
  return config.issuance.credential_types.map((credentialType) =>
    IssuerTestConfiguration.createCustom({
      authorizeStepClass: getStepClass(
        customSteps,
        "authorize",
        AuthorizeDefaultStep,
      ),
      credentialConfigurationId: credentialType,
      credentialRequestStepClass: getStepClass(
        customSteps,
        "credentialRequest",
        CredentialRequestDefaultStep,
      ),
      fetchMetadataStepClass: getStepClass(
        customSteps,
        "fetchMetadata",
        FetchMetadataDefaultStep,
      ),
      name: `${flowName} - ${credentialType}`,
      nonceRequestStepClass: getStepClass(
        customSteps,
        "nonceRequest",
        NonceRequestDefaultStep,
      ),
      pushedAuthorizationRequestStepClass: getStepClass(
        customSteps,
        "pushedAuthorizationRequest",
        PushedAuthorizationRequestDefaultStep,
      ),
      tokenRequestStepClass: getStepClass(
        customSteps,
        "tokenRequest",
        TokenRequestDefaultStep,
      ),
    }),
  );
}

/**
 * Builds a presentation test configuration from custom steps.
 *
 * @param flowName The test flow name
 * @param customSteps Discovered custom step classes
 * @returns Presentation test configuration
 */
function buildPresentationTestConfiguration(
  flowName: string,
  customSteps: CustomStepsMap,
): PresentationTestConfiguration {
  return PresentationTestConfiguration.createCustom({
    authorizeStepClass: getStepClass(
      customSteps,
      "authorizationRequest",
      AuthorizationRequestDefaultStep,
    ),
    fetchMetadataStepClass: getStepClass(
      customSteps,
      "fetchMetadata",
      FetchMetadataDefaultStep,
    ),
    name: flowName,
    redirectUriStepClass: getStepClass(
      customSteps,
      "redirectUri",
      RedirectUriDefaultStep,
    ),
  });
}

/**
 * Creates a helpful error message when no steps directory is configured.
 *
 * @param flowName The test flow name
 * @returns Formatted error message with configuration examples
 */
function createDirectoryErrorMessage(flowName: string): string {
  return (
    `No steps_mapping entry found for test '${flowName}' and no default_steps_dir configured.\n` +
    `Please add one of the following to your config.ini:\n\n` +
    `Option 1 - Specific mapping:\n` +
    `[steps_mapping]\n` +
    `${flowName} = tests/steps/version_1_0/issuance\n\n` +
    `Option 2 - Default directory (used when specific mapping is not found):\n` +
    `[steps_mapping]\n` +
    `default_steps_dir = tests/steps/version_1_0\n\n` +
    `See TEST-CONFIGURATION-GUIDE.md for details.`
  );
}

/**
 * Type-safe helper to get a step class from discovered steps or use default fallback
 * @param discovered Map of discovered custom steps
 * @param key Key to look up in the discovered steps
 * @param fallback Default step class to use if not found
 * @returns The discovered step class or fallback
 */
function getStepClass<T extends StepClass>(
  discovered: CustomStepsMap,
  key: string,
  fallback: T,
): T {
  const discoveredStep = discovered[key];
  if (discoveredStep) {
    // Runtime validation: discovered step should be compatible with fallback
    return discoveredStep as T;
  }
  return fallback;
}

/**
 * Merges two step maps, with primary steps taking precedence over fallback steps.
 * This is a pure function with no side effects.
 *
 * @param primary Primary step map (takes precedence)
 * @param fallback Fallback step map (used for missing steps)
 * @returns Merged step map
 */
function mergeStepMaps(
  primary: CustomStepsMap,
  fallback: CustomStepsMap,
): CustomStepsMap {
  return { ...fallback, ...primary };
}

/**
 * Resolves both primary and fallback directories for step discovery.
 *
 * @param flowName The test flow name
 * @param config The loaded configuration
 * @returns Object with primary directory path and optional fallback path
 */
function resolveStepDirectories(
  flowName: string,
  config: Config,
): { fallback?: string; primary: string } {
  const mappedPath = config.steps_mapping?.mapping?.[flowName];
  const defaultPath = config.steps_mapping?.default_steps_dir;

  // Validate that we have at least one path configured
  if (!mappedPath && !defaultPath) {
    throw new Error(createDirectoryErrorMessage(flowName));
  }

  // Resolve the primary directory
  const primary = mappedPath
    ? path.resolve(process.cwd(), mappedPath)
    : path.resolve(process.cwd(), defaultPath!);

  // Resolve the fallback directory (if different from primary)
  const fallback =
    mappedPath && defaultPath
      ? path.resolve(process.cwd(), defaultPath)
      : undefined;

  // Log the resolution
  if (mappedPath) {
    log.info(`steps_mapping: resolved '${flowName}' -> ${primary}`);
  } else {
    log.info(
      `steps_mapping: using default_steps_dir for '${flowName}' -> ${primary}`,
    );
  }

  return { fallback: fallback !== primary ? fallback : undefined, primary };
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
