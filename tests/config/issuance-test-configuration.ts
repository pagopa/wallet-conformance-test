import { FetchMetadataOptions } from "@/step/issuance/fetch-metadata-step";
import { PushedAuthorizationRequestOptions } from "@/step/issuance/pushed-authorization-request-step";

/**
 * Configuration class for Issuer conformance tests
 */
export class IssuerTestConfiguration {
  /**
   * Credential configuration id to use in the test
   */
  public readonly credentialConfigurationId: string;

  /**
   * Optional fetch metadata options
   */
  public readonly fetchMetadataOptions?: FetchMetadataOptions;

  /**
   * Optional pushed authorization request options
   */
  public readonly pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;

  /**
   * Name of the test (used for logging and identification)
   */
  public readonly testName: string;

  constructor(config: {
    credentialConfigurationId: string;
    fetchMetadataOptions?: FetchMetadataOptions;
    pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;
    testName: string;
  }) {
    this.testName = config.testName;
    this.credentialConfigurationId = config.credentialConfigurationId;
    this.fetchMetadataOptions = config.fetchMetadataOptions;
    this.pushedAuthorizationRequestOptions =
      config.pushedAuthorizationRequestOptions;
  }

  /**
   * Create a custom configuration
   */
  static createCustom(config: {
    credentialConfigurationId: string;
    fetchMetadataOptions?: FetchMetadataOptions;
    pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;
    testName: string;
  }): IssuerTestConfiguration {
    return new IssuerTestConfiguration(config);
  }

  /**
   * Create a configuration with default values
   */
  static createDefault(): IssuerTestConfiguration {
    return new IssuerTestConfiguration({
      credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
      testName: "Issuance Happy Flow",
    });
  }

  /**
   * Convert the configuration to the format expected by IssuerOrchestratorFlow.runAll()
   */
  toRunOptions() {
    return {
      credentialConfigurationId: this.credentialConfigurationId,
      fetchMetadataOptions: this.fetchMetadataOptions,
      pushedAuthorizationRequestOptions: this.pushedAuthorizationRequestOptions,
      testName: this.testName,
    };
  }
}
