/**
 * Test Configuration File
 *
 * This is where you register your test configurations.
 * Create your configurations and register them to run the tests.
 *
 * The registered configurations will be picked up by the test suite.
 */

import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { PresentationTestConfiguration } from "./config/presentation-test-configuration";
import { issuerRegistry, presentationRegistry } from "./config/test-registry";

// ============================================================================
// DEFINE YOUR TEST CONFIGURATIONS HERE -- ISSUANCE
// ============================================================================

// const happyFlowPIDConfig = IssuerTestConfiguration.createDefault();

const happyFlowCredentialConfig = IssuerTestConfiguration.createCustom({
  credentialConfigurationId: "dc_sd_jwt_EuropeanDisabilityCard",
  name: "Happy Flow EuropeanDisabilityCard Test",
});

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
*/

// ============================================================================
// DEFINE YOUR FLOW TEST NAME HERE -- ISSUANCE
// ============================================================================

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest"; // Reference to happy.issuance.spec.ts

/**
 * Example 1: Register test on HappyFlowIssuanceTest
 */
//issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, happyFlowPIDConfig);

/**
 * Example 2: Register test on HappyFlowMdlTest
 */
issuerRegistry.registerTest(
  HAPPY_FLOW_ISSUANCE_NAME,
  happyFlowCredentialConfig,
);

/**
 * Example 3: Register test on FailedMetadataFetchTest
 
issuerRegistry.registerTest("FailedMetadataFetchTest", failedMetadataConfig);
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
