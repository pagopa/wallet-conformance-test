import { FetchMetadataDefaultStep } from "@/step/issuance";
import {
  AuthorizeDefaultStep,
  CredentialRequestDefaultStep,
  NonceRequestDefaultStep,
  PushedAuthorizationRequestDefaultStep,
  TokenRequestDefaultStep,
} from "@/step/issuance";

/**
 * Configuration class for Issuer conformance tests
 */
export class IssuerTestConfiguration {
  public readonly authorizeStepClass: typeof AuthorizeDefaultStep;
  public readonly credentialConfigurationId: string;

  public readonly credentialRequestStepClass: typeof CredentialRequestDefaultStep;
  public readonly fetchMetadataStepClass: typeof FetchMetadataDefaultStep;
  public readonly name: string;
  public readonly nonceRequestStepClass: typeof NonceRequestDefaultStep;
  public readonly pushedAuthorizationRequestStepClass: typeof PushedAuthorizationRequestDefaultStep;
  public readonly tokenRequestStepClass: typeof TokenRequestDefaultStep;

  constructor(config: {
    authorizeStepClass: typeof AuthorizeDefaultStep;
    credentialConfigurationId: string;
    credentialRequestStepClass: typeof CredentialRequestDefaultStep;
    fetchMetadataStepClass: typeof FetchMetadataDefaultStep;
    name: string;
    nonceRequestStepClass: typeof NonceRequestDefaultStep;
    pushedAuthorizationRequestStepClass: typeof PushedAuthorizationRequestDefaultStep;
    tokenRequestStepClass: typeof TokenRequestDefaultStep;
  }) {
    this.name = config.name;
    this.credentialConfigurationId = config.credentialConfigurationId;

    this.fetchMetadataStepClass = config.fetchMetadataStepClass;
    this.pushedAuthorizationRequestStepClass =
      config.pushedAuthorizationRequestStepClass;
    this.authorizeStepClass = config.authorizeStepClass;
    this.tokenRequestStepClass = config.tokenRequestStepClass;
    this.nonceRequestStepClass = config.nonceRequestStepClass;
    this.credentialRequestStepClass = config.credentialRequestStepClass;
  }

  static createCustom(
    config: ConstructorParameters<typeof IssuerTestConfiguration>[0],
  ) {
    return new IssuerTestConfiguration(config);
  }

  static createDefault(): IssuerTestConfiguration {
    return new IssuerTestConfiguration({
      authorizeStepClass: AuthorizeDefaultStep,
      credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
      credentialRequestStepClass: CredentialRequestDefaultStep,
      fetchMetadataStepClass: FetchMetadataDefaultStep,
      name: "Issuance Happy Flow",
      nonceRequestStepClass: NonceRequestDefaultStep,
      pushedAuthorizationRequestStepClass:
        PushedAuthorizationRequestDefaultStep,
      tokenRequestStepClass: TokenRequestDefaultStep,
    });
  }
}
