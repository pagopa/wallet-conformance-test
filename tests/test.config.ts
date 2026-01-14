/**
 * Test Configuration File
 *
 * This is where you register your test configurations.
 * Configurations are dynamically loaded from config.ini or CLI options.
 *
 * The registered configurations will be picked up by the test suite.
 */

import { loadConfigWithHierarchy } from "@/logic/config-loader";

import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { PresentationTestConfiguration } from "./config/presentation-test-configuration";
import { issuerRegistry, presentationRegistry } from "./config/test-registry";

// ============================================================================
// LOAD CONFIGURATION AND CREDENTIAL TYPES
// ============================================================================

const config = loadConfigWithHierarchy();

// Default credential type for backward compatibility
const DEFAULT_CREDENTIAL_TYPES = ["dc_sd_jwt_EuropeanDisabilityCard"];

// Use configured credential types, or fall back to default
const credentialTypes =
  config.issuance.credential_types &&
  config.issuance.credential_types.length > 0
    ? config.issuance.credential_types
    : DEFAULT_CREDENTIAL_TYPES;

// ============================================================================
// DEFINE YOUR FLOW TEST NAME HERE -- ISSUANCE
// ============================================================================

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest"; // Reference to happy.issuance.spec.ts

// ============================================================================
// DYNAMICALLY REGISTER TEST CONFIGURATIONS -- ISSUANCE
// ============================================================================

/**
 * Register a test configuration for each credential type.
 * Credential types are loaded from:
 * 1. CLI option --credential-types (highest priority)
 * 2. config.ini issuance.credential_types[]
 * 3. Default: dc_sd_jwt_PersonIdentificationData
 */
for (const credentialType of credentialTypes) {
  const testConfig = IssuerTestConfiguration.createCustom({
    credentialConfigurationId: credentialType,
    name: `Happy Flow ${credentialType} Test`,
  });

  issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, testConfig);
}

/**
 * Example: Failed Configuration - Invalid Metadata Fetch

const failedMetadataConfig = IssuerTestConfiguration.createCustom({
  testName: "Failed Metadata Fetch Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
  fetchMetadata: {
    options: {
      wellKnownPath: "/.well-known/invalid-path",
    }
  },
});

issuerRegistry.registerTest("FailedMetadataFetchTest", failedMetadataConfig);
 */

/**
 * Example: Alternative Step Configuration - Return hardcoded entity metadata

import { FetchMetadataHardcodedStep } from "@/step/issuance/fetch-metadata-hardcoded-step";

const hardcodedMetadataConfig = IssuerTestConfiguration.createCustom({
  testName: "Hardcoded Metadata Fetch Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
  fetchMetadata: {
    stepClass: FetchMetadataHardcodedStep,
  },
});

issuerRegistry.registerTest("HardcodedMetadataFetchTest", hardcodedMetadataConfig);
*/

// ============================================================================
// DEFINE YOUR FLOW TEST NAME HERE -- PRESENTATION
// ============================================================================

export const HAPPY_FLOW_PRESENTATION_NAME = "HappyFlowPresentationTest"; // Reference to happy.presentation.spec.ts

// ============================================================================
// REGISTER YOUR TEST CONFIGURATIONS HERE
// ============================================================================

/**
 * Example 1: Register test on HappyFlowPresentationTest
 */
presentationRegistry.registerTest(
  HAPPY_FLOW_PRESENTATION_NAME,
  PresentationTestConfiguration.createDefault(),
);

// ============================================================================
// END OF CONFIGURATION
// ============================================================================

/**
 * Do not modify below this line unless you know what you're doing.
 * The configuration is automatically loaded by the test suite.
 */
