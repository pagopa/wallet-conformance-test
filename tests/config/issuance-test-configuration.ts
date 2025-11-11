import { FetchMetadataOptions } from "@/step/issuance/fetch-metadata-step";
import { PushedAuthorizationRequestOptions } from "@/step/issuance/pushed-authorization-request-step";

/**
 * Configuration for credential issuance
 */
export interface CredentialConfiguration {
  /**
   * The credential configuration ID as defined by the issuer
   */
  id: string;

  /**
   * The scope to request for this credential
   */
  scope: string;
}

/**
 * Configuration class for Issuer conformance tests
 */
export class IssuerTestConfiguration {
  /**
   * Credential configuration to use in the test
   */
  public readonly credentialConfiguration: CredentialConfiguration;

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
    credentialConfiguration: CredentialConfiguration;
    fetchMetadataOptions?: FetchMetadataOptions;
    pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;
    testName: string;
  }) {
    this.testName = config.testName;
    this.credentialConfiguration = config.credentialConfiguration;
    this.fetchMetadataOptions = config.fetchMetadataOptions;
    this.pushedAuthorizationRequestOptions =
      config.pushedAuthorizationRequestOptions;
  }

  /**
   * Create a custom configuration
   */
  static createCustom(config: {
    credentialConfiguration: CredentialConfiguration;
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
      credentialConfiguration: {
        id: "dc_sd_jwt_PersonIdentificationData",
        scope: "PersonIdentificationData",
      },
      testName: "Issuance Happy Flow",
    });
  }

  /**
   * Convert the configuration to the format expected by IssuerOrchestratorFlow.runAll()
   */
  toRunOptions() {
    return {
      credentialConfiguration: this.credentialConfiguration,
      fetchMetadataOptions: this.fetchMetadataOptions,
      pushedAuthorizationRequestOptions: this.pushedAuthorizationRequestOptions,
      testName: this.testName,
    };
  }
}
