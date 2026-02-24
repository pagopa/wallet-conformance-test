import { IssuerTestConfiguration } from "#/config";
import {
  AccessTokenRequest,
  createClientAttestationPopJwt,
} from "@pagopa/io-wallet-oauth2";
import { resolveCredentialOffer } from "@pagopa/io-wallet-oid4vci";

import { createMockSdJwt, loadAttestation, loadCredentials } from "@/functions";
import {
  buildJwksPath,
  createLogger,
  loadConfigWithHierarchy,
  loadJwks,
  partialCallbacks,
  saveCredentialToDisk,
  signJwtCallback,
} from "@/logic";
import { FetchMetadataDefaultStep, FetchMetadataStepResponse } from "@/step";
import {
  AuthorizeDefaultStep,
  AuthorizeStepResponse,
  CredentialRequestDefaultStep,
  CredentialRequestResponse,
  NonceRequestDefaultStep,
  NonceRequestResponse,
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestResponse,
  TokenRequestDefaultStep,
  TokenRequestResponse,
} from "@/step/issuance";
import { AttestationResponse, Config, Credential } from "@/types";

export class WalletIssuanceOrchestratorFlow {
  private authorizeStep: AuthorizeDefaultStep;
  private config: Config;
  private credentialRequestStep: CredentialRequestDefaultStep;
  private fetchMetadataStep: FetchMetadataDefaultStep;
  private issuanceConfig: IssuerTestConfiguration;
  private log = createLogger();

  private nonceRequestStep: NonceRequestDefaultStep;
  private pushedAuthorizationRequestStep: PushedAuthorizationRequestDefaultStep;
  private tokenRequestStep: TokenRequestDefaultStep;

  constructor(issuanceConfig: IssuerTestConfiguration) {
    this.issuanceConfig = issuanceConfig;
    this.log = this.log.withTag(this.issuanceConfig.name);

    this.config = loadConfigWithHierarchy();

    this.log.setLogOptions({
      format: this.config.logging.log_format,
      level: this.config.logging.log_level,
      path: this.config.logging.log_file,
    });

    this.log.debug("Setting Up Wallet conformance Tests - Issuance Flow");
    this.log.debug(
      "Configuration Loaded (Hierarchy: CLI options > Custom INI > Default INI)",
    );

    this.log.debug(
      "Configuration Loaded:\n",
      JSON.stringify({
        credentialsDir: this.config.wallet.credentials_storage_path,
        issuanceUrl: this.config.issuance.url,
        maxRetries: this.config.network.max_retries,
        timeout: `${this.config.network.timeout}s`,
        userAgent: this.config.network.user_agent,
      }),
    );

    this.fetchMetadataStep = new issuanceConfig.fetchMetadataStepClass(
      this.config,
      this.log,
    );

    this.pushedAuthorizationRequestStep =
      new issuanceConfig.pushedAuthorizationRequestStepClass(
        this.config,
        this.log,
      );

    this.authorizeStep = new issuanceConfig.authorizeStepClass(
      this.config,
      this.log,
    );
    this.tokenRequestStep = new issuanceConfig.tokenRequestStepClass(
      this.config,
      this.log,
    );

    this.nonceRequestStep = new issuanceConfig.nonceRequestStepClass(
      this.config,
      this.log,
    );

    this.credentialRequestStep = new issuanceConfig.credentialRequestStepClass(
      this.config,
      this.log,
    );
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async issuance(): Promise<{
    authorizeResponse: AuthorizeStepResponse;
    credentialResponse: CredentialRequestResponse;
    fetchMetadataResponse: FetchMetadataStepResponse;
    nonceResponse: NonceRequestResponse;
    pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    tokenResponse: TokenRequestResponse;
    walletAttestationResponse: AttestationResponse;
  }> {
    try {
      this.log.info("Starting Test Issuance Flow...");

      let credentialIssuer: string;
      let credentialConfigurationIds: string[];
      if (
        this.config.issuance.credential_offer_uri &&
        this.config.issuance.credential_offer_uri !== ""
      ) {
        this.log.info(
          `Resolving Credential Offer: ${this.config.issuance.credential_offer_uri}`,
        );
        const credentialOffer = await resolveCredentialOffer({
          callbacks: { fetch },
          credentialOffer: this.config.issuance.credential_offer_uri,
        });
        this.log.debug(
          "Received Credential Offer:\n",
          JSON.stringify(credentialOffer),
        );

        credentialIssuer = credentialOffer.credential_issuer;
        credentialConfigurationIds =
          credentialOffer.credential_configuration_ids;

        if (credentialConfigurationIds.length === 0)
          throw new Error(
            "Cannot proceed: The credential offer returned no credential configuration IDs",
          );
      } else {
        this.log.debug(
          "Missing Credential Offer URI: using Credetntial Issuer and Credential ID from configuration",
        );

        credentialIssuer = this.config.issuance.url;
        credentialConfigurationIds = [
          this.issuanceConfig.credentialConfigurationId,
        ];

        if (credentialConfigurationIds.length === 0)
          throw new Error(
            "Cannot proceed: credential configuration id was not defined",
          );
      }
      this.log.info(
        `Requesting credentials ${JSON.stringify(credentialConfigurationIds)} from issuer ${credentialIssuer}`,
      );

      const fetchMetadataResponse = await this.fetchMetadataStep.run({
        baseUrl: credentialIssuer,
      });
      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.trust_anchor.port}`;

      const walletAttestationResponse = await loadAttestation({
        trustAnchorBaseUrl,
        trustAnchorJwksPath:
          this.config.trust.federation_trust_anchors_jwks_path,
        wallet: this.config.wallet,
      });

      const callbacks = {
        ...partialCallbacks,
        signJwt: signJwtCallback([
          walletAttestationResponse.unitKey.privateKey,
        ]),
      };

      const entityStatementClaims =
        fetchMetadataResponse.response?.entityStatementClaims;
      if (!entityStatementClaims) {
        throw new Error("Entity Statement Claims not found in response");
      }

      // Validate credentialConfigurationId is supported by the issuer
      const credentialConfigsSupported =
        entityStatementClaims.metadata?.openid_credential_issuer
          ?.credential_configurations_supported;

      if (credentialConfigsSupported) {
        const supportedIds = Object.keys(credentialConfigsSupported);
        const requestedId = this.issuanceConfig.credentialConfigurationId;

        if (!supportedIds.includes(requestedId)) {
          throw new Error(
            `Credential configuration '${requestedId}' is not supported by the issuer.\n` +
              `Supported credential configurations: ${supportedIds.join(", ")}\n` +
              `Please update your test configuration with a valid credentialConfigurationId.`,
          );
        }

        if (
          this.config.issuance.credential_offer_uri &&
          !credentialConfigurationIds.includes(requestedId)
        ) {
          throw new Error(
            `Credential configuration '${requestedId}' is configured in your test but was not ` +
              `included in the credential offer (credential_offer_uri).\n` +
              `Offer includes: ${credentialConfigurationIds.join(", ")}\n` +
              `Please check that your credential_offer_uri targets the correct credential.`,
          );
        }
      } else
        this.log.warn(
          "Warning: Could not verify credentialConfigurationId - " +
            "credential_configurations_supported not found in issuer metadata",
        );

      const clientAttestationDPoP = await createClientAttestationPopJwt({
        authorizationServer: entityStatementClaims.iss,
        callbacks,
        clientAttestation: walletAttestationResponse.attestation,
      });

      const pushedAuthorizationRequestResponse =
        await this.pushedAuthorizationRequestStep.run({
          baseUrl: credentialIssuer,
          clientId: walletAttestationResponse.unitKey.publicKey.kid,
          credentialConfigurationIds,
          popAttestation: clientAttestationDPoP,
          pushedAuthorizationRequestEndpoint:
            entityStatementClaims.metadata?.oauth_authorization_server
              ?.pushed_authorization_request_endpoint,
          walletAttestation: walletAttestationResponse,
        });

      if (!pushedAuthorizationRequestResponse.response)
        throw new Error("Pushed Authorization Request failed");

      const code_verifier = pushedAuthorizationRequestResponse.codeVerifier;
      if (!code_verifier)
        throw new Error(
          "Pushed Authorization Request Step step did not return a code_verifier. " +
            "Check the PAR Step step for errors.",
        );

      this.log.debug(
        `Code Verifier generated for Pushed Authorization '${pushedAuthorizationRequestResponse.codeVerifier}'`,
      );

      this.log.info("Loading credentials...");
      let personIdentificationData: Credential;
      const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";

      try {
        const credentials = await loadCredentials(
          this.config.wallet.credentials_storage_path,
          [credentialIdentifier],
          this.log.debug,
        );

        if (credentials.dc_sd_jwt_PersonIdentificationData)
          personIdentificationData =
            credentials.dc_sd_jwt_PersonIdentificationData;
        else {
          this.log.debug("missing pid: creating new one");
          throw new Error("missing pid: creating new one");
        }
      } catch {
        personIdentificationData = await createMockSdJwt(
          {
            iss: "https://issuer.example.com",
            trustAnchorBaseUrl,
            trustAnchorJwksPath:
              this.config.trust.federation_trust_anchors_jwks_path,
          },
          this.config.wallet.backup_storage_path,
          this.config.wallet.credentials_storage_path,
        );
      }

      const credentialKeyPair = await loadJwks(
        this.config.wallet.backup_storage_path,
        buildJwksPath(credentialIdentifier),
      );

      const authorizeResponse = await this.authorizeStep.run({
        authorizationEndpoint:
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.authorization_endpoint,
        baseUrl: credentialIssuer,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentials: [
          {
            credential: personIdentificationData.compact,
            keyPair: credentialKeyPair,
            typ: "dc+sd-jwt",
          },
        ],
        requestUri: pushedAuthorizationRequestResponse.response?.request_uri,
        rpMetadata: entityStatementClaims.metadata?.openid_credential_verifier,
        walletAttestation: walletAttestationResponse,
      });

      const code = authorizeResponse.response?.authorizeResponse?.code;
      if (!code)
        throw new Error(
          "Authorization step did not return a code. " +
            "Check the authorize step for errors.",
        );

      const redirect_uri =
        authorizeResponse.response?.requestObject?.response_uri;
      if (!redirect_uri)
        throw new Error(
          "Authorization step did not return a redirect_uri. " +
            "Check the authorize step for errors.",
        );

      const accessTokenRequest: AccessTokenRequest = {
        code,
        code_verifier,
        grant_type: "authorization_code",
        redirect_uri,
      };

      const tokenResponse = await this.tokenRequestStep.run({
        accessTokenEndpoint:
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.token_endpoint,
        accessTokenRequest,
        popAttestation: clientAttestationDPoP,
        walletAttestation: walletAttestationResponse,
      });

      const accessToken = tokenResponse.response?.access_token;
      if (!accessToken)
        throw new Error(
          "Token step did not return a redirect_uri. " +
            "Check the token step for errors.",
        );

      const nonceResponse = await this.nonceRequestStep.run({
        nonceEndpoint:
          entityStatementClaims.metadata?.openid_credential_issuer
            ?.nonce_endpoint,
      });

      const nonce = nonceResponse.response?.nonce as
        | undefined
        | { c_nonce: string };
      if (!nonce)
        throw new Error(
          "Nonce step did not return a redirect_uri. " +
            "Check the nonce step for errors.",
        );

      const credentialResponse = await this.credentialRequestStep.run({
        accessToken,
        baseUrl: credentialIssuer,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialIdentifier: this.issuanceConfig.credentialConfigurationId,
        credentialRequestEndpoint:
          entityStatementClaims.metadata?.openid_credential_issuer
            ?.credential_endpoint,
        nonce: nonce.c_nonce,
        walletAttestation: walletAttestationResponse,
      });

      // Save credential to disk if configured
      // Currently, only the first credential is saved because we support requesting one at a time
      const firstCredential = credentialResponse.response?.credentials?.[0];
      if (this.config.issuance.save_credential && firstCredential?.credential) {
        const savedPath = saveCredentialToDisk(
          this.config.wallet.credentials_storage_path,
          this.issuanceConfig.credentialConfigurationId,
          firstCredential.credential,
        );
        if (savedPath) {
          this.log.info(`Credential saved to disk: ${savedPath}`);
        } else {
          this.log.error("Failed to save credential to disk");
        }
      }

      return {
        authorizeResponse,
        credentialResponse,
        fetchMetadataResponse,
        nonceResponse,
        pushedAuthorizationRequestResponse,
        tokenResponse,
        walletAttestationResponse,
      };
    } catch (e) {
      this.log.error("Error in Issuer Flow Tests!", e);
      throw e;
    }
  }
}
