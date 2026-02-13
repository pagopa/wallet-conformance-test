import { IssuerTestConfiguration } from "#/config";
import {
  AccessTokenRequest,
  createClientAttestationPopJwt,
} from "@pagopa/io-wallet-oauth2";

import { createMockSdJwt, loadAttestation, loadCredentials } from "@/functions";
import {
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
  AuthorizeStepOptions,
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
import { AttestationResponse, Config } from "@/types";

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

    this.log.info("Setting Up Wallet conformance Tests - Issuance Flow");
    this.log.info(
      "Configuration Loaded (Hierarchy: CLI options > Custom INI > Default INI)",
    );

    this.log.info(
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

      const fetchMetadataResponse = await this.fetchMetadataStep.run({
        baseUrl: this.config.issuance.url,
      });
      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.trust_anchor.port}`;

      this.log.info("Loading Wallet Attestation...");
      const walletAttestationResponse = await loadAttestation({
        trustAnchorBaseUrl,
        trustAnchorJwksPath:
          this.config.trust.federation_trust_anchors_jwks_path,
        wallet: this.config.wallet,
      });
      this.log.info("Wallet Attestation Loaded.");

      this.log.info("Creating Client Attestation DPoP...");
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

        this.log.info(
          `Credential configuration '${requestedId}' validated as supported by issuer`,
        );
      } else {
        this.log.warn(
          "Warning: Could not verify credentialConfigurationId - " +
            "credential_configurations_supported not found in issuer metadata",
        );
      }

      const clientAttestationDPoP = await createClientAttestationPopJwt({
        authorizationServer: entityStatementClaims.iss,
        callbacks,
        clientAttestation: walletAttestationResponse.attestation,
      });

      this.log.info("Sending Pushed Authorization Request...");

      const pushedAuthorizationRequestResponse =
        await this.pushedAuthorizationRequestStep.run({
          clientId: walletAttestationResponse.unitKey.publicKey.kid,
          credentialConfigurationId:
            this.issuanceConfig.credentialConfigurationId,
          popAttestation: clientAttestationDPoP,
          pushedAuthorizationRequestEndpoint:
            entityStatementClaims.metadata?.oauth_authorization_server
              ?.pushed_authorization_request_endpoint,
          walletAttestation: walletAttestationResponse,
        });

      if (!pushedAuthorizationRequestResponse.response) {
        throw new Error("Pushed Authorization Request failed");
      }

      this.log.info(
        `Code Verifier generated for Pushed Authorization '${pushedAuthorizationRequestResponse.codeVerifier}'`,
      );

      const credentials: AuthorizeStepOptions["credentials"] = [];

      try {
        const storedCredentials = await loadCredentials(
          this.config.wallet.credentials_storage_path,
          [],
          this.log.debug,
        );

        for (const [key, cred] of Object.entries(storedCredentials)) {
          const credentialKeyPair = await loadJwks(
            this.config.wallet.backup_storage_path,
            `${key}_jwks`,
          );

          credentials.push({
            credential: cred.compact,
            keyPair: credentialKeyPair,
            typ: cred.typ,
          });
        }

        if (credentials.length === 0) throw new Error();
      } catch {
        const personIdentificationData = await createMockSdJwt(
          {
            iss: "https://issuer.example.com",
            trustAnchorBaseUrl,
            trustAnchorJwksPath:
              this.config.trust.federation_trust_anchors_jwks_path,
          },
          this.config.wallet.backup_storage_path,
          this.config.wallet.credentials_storage_path,
        );

        const credentialKeyPair = await loadJwks(
          this.config.wallet.backup_storage_path,
          `dc_sd_jwt_PersonIdentificationData_jwks`,
        );

        credentials.push({
          credential: personIdentificationData.compact,
          keyPair: credentialKeyPair,
          typ: personIdentificationData.typ,
        });
      }

      const authorizeResponse = await this.authorizeStep.run({
        authorizationEndpoint:
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.authorization_endpoint,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentials,
        requestUri: pushedAuthorizationRequestResponse.response?.request_uri,
        rpMetadata: entityStatementClaims.metadata?.openid_credential_verifier,
        walletAttestation: walletAttestationResponse,
      });

      const accessTokenRequest: AccessTokenRequest = {
        code: authorizeResponse.response?.authorizeResponse?.code ?? "",
        code_verifier: pushedAuthorizationRequestResponse.codeVerifier ?? "",
        grant_type: "authorization_code",
        redirect_uri:
          authorizeResponse.response?.requestObject?.response_uri ?? "",
      };
      const tokenResponse = await this.tokenRequestStep.run({
        accessTokenEndpoint:
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.token_endpoint,
        accessTokenRequest,
        popAttestation: clientAttestationDPoP,
        walletAttestation: walletAttestationResponse,
      });

      const nonceResponse = await this.nonceRequestStep.run({
        nonceEndpoint:
          entityStatementClaims.metadata?.openid_credential_issuer
            ?.nonce_endpoint,
      });

      const nonce = nonceResponse.response?.nonce as
        | undefined
        | { c_nonce: string };

      const credentialResponse = await this.credentialRequestStep.run({
        accessToken: tokenResponse.response?.access_token ?? "",
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialIdentifier: this.issuanceConfig.credentialConfigurationId,
        credentialRequestEndpoint:
          entityStatementClaims.metadata?.openid_credential_issuer
            ?.credential_endpoint,
        nonce: nonce?.c_nonce ?? "",
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
