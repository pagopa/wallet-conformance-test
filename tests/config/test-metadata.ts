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
import {
  FetchMetadataDefaultStep,
  PushedAuthorizationRequestDefaultStep,
  TokenRequestDefaultStep,
} from "@/step/issuance";
import { AuthorizeDefaultStep } from "@/step/issuance/authorize-step";
import { CredentialRequestDefaultStep } from "@/step/issuance/credential-request-step";
import { NonceRequestDefaultStep } from "@/step/issuance/nonce-request-step";
import { AuthorizationRequestDefaultStep } from "@/step/presentation/authorization-request-step";
import { FetchMetadataVpDefaultStep } from "@/step/presentation/fetch-metadata-step";
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

    // Discover custom steps from the mapped directory (if any)
    const customStepsDir = resolveStepDirectory(name, config);
    const customSteps = customStepsDir
      ? await testLoader.discoverCustomSteps(customStepsDir)
      : {};

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

    // Discover custom steps from the mapped directory (if any)
    const customStepsDir = resolveStepDirectory(name, config);
    const customSteps = customStepsDir
      ? await testLoader.discoverCustomSteps(customStepsDir)
      : {};

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
      "fetchMetadataVp",
      FetchMetadataVpDefaultStep,
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
 * Resolves the custom steps directory for a given flow name, if configured.
 * Returns undefined when no steps_mapping entry exists for the flow — in that
 * case the caller will use the built-in *DefaultStep classes automatically.
 *
 * @param flowName The test flow name
 * @param config The loaded configuration
 * @returns Absolute path to the custom steps directory, or undefined
 */
function resolveStepDirectory(
  flowName: string,
  config: Config,
): string | undefined {
  const mappedPath = config.steps_mapping?.mapping?.[flowName];
  if (!mappedPath) {
    log.info(
      `steps_mapping: no entry for '${flowName}', using built-in default steps`,
    );
    return undefined;
  }
  const resolved = path.resolve(process.cwd(), mappedPath);
  log.info(`steps_mapping: resolved '${flowName}' -> ${resolved}`);
  return resolved;
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
