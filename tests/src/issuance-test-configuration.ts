import { FetchMetadataOptions } from "./step/issuing/fetch-metadata-step";
import { PushedAuthorizationRequestOptions } from "./step/issuing/pushed-authorization-request-step";

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
   * Name of the test (used for logging and identification)
   */
  public readonly testName: string;

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

  constructor(config: {
    testName: string;
    credentialConfiguration: CredentialConfiguration;
    fetchMetadataOptions?: FetchMetadataOptions;
    pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;
  }) {
    this.testName = config.testName;
    this.credentialConfiguration = config.credentialConfiguration;
    this.fetchMetadataOptions = config.fetchMetadataOptions;
    this.pushedAuthorizationRequestOptions =
      config.pushedAuthorizationRequestOptions;
  }

  /**
   * Convert the configuration to the format expected by IssuerOrchestratorFlow.runAll()
   */
  toRunOptions() {
    return {
      testName: this.testName,
      credentialConfiguration: this.credentialConfiguration,
      fetchMetadataOptions: this.fetchMetadataOptions,
      pushedAuthorizationRequestOptions: this.pushedAuthorizationRequestOptions,
    };
  }

  /**
   * Create a configuration with default values
   */
  static createDefault(): IssuerTestConfiguration {
    return new IssuerTestConfiguration({
      testName: "Issuance Happy Flow",
      credentialConfiguration: {
        id: "dc_sd_jwt_PersonIdentificationData",
        scope: "PersonIdentificationData",
      },
    });
  }

  /**
   * Create a custom configuration
   */
  static createCustom(config: {
    testName: string;
    credentialConfiguration: CredentialConfiguration;
    fetchMetadataOptions?: FetchMetadataOptions;
    pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;
  }): IssuerTestConfiguration {
    return new IssuerTestConfiguration(config);
  }
}
