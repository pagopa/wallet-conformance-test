/**
 * Test Configuration File
 *
 * This is where you register your test configurations.
 * Create your configurations and register them to run the tests.
 *
 * The registered configurations will be picked up by the test suite.
 */

import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { registerTest } from "./config/issuance-test-registry";

// ============================================================================
// DEFINE YOUR TEST CONFIGURATIONS HERE
// ============================================================================

const happyFlowPIDConfig = IssuerTestConfiguration.createDefault();

const happyFlowMdlConfig = IssuerTestConfiguration.createCustom({
  credentialConfigurationId: "dc_sd_jwt_DrivingLicense",
  testName: "Happy Flow mDL Test",
});

/**
 * Example: Failed Configuration - Invalid Metadata Fetch
 
const failedMetadataConfig = IssuerTestConfiguration.createCustom({
  testName: "Failed Metadata Fetch Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
  fetchMetadataOptions: {
    wellKnownPath: "/.well-known/invalid-path",
  },
});
*/

// ============================================================================
// DEFINE YOUR FLOW TEST NAME HERE
// ============================================================================

export const HAPPY_FLOW_NAME = "HappyFlowIssuanceTest"; //Reference to happy-flow.issuance.spec.ts

// ============================================================================
// REGISTER YOUR TEST CONFIGURATIONS HERE
// ============================================================================

/**
 * Example 1: Register test on HappyFlowIssuanceTest
 */
registerTest(HAPPY_FLOW_NAME, happyFlowPIDConfig);

/**
 * Example 2: Register test on HappyFlowMdlTest
 */
registerTest(HAPPY_FLOW_NAME, happyFlowMdlConfig);

/**
 * Example 3: Register test on FailedMetadataFetchTest
 
registerTest("FailedMetadataFetchTest", failedMetadataConfig);
*/

// ============================================================================
// END OF CONFIGURATION
// ============================================================================

/**
 * Do not modify below this line unless you know what you're doing.
 * The configuration is automatically loaded by the test suite.
 */
