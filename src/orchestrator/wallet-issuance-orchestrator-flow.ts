import { IssuerTestConfiguration } from "#/config";
import {
  AccessTokenRequest,
  createClientAttestationPopJwt,
} from "@pagopa/io-wallet-oauth2";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";

import { createMockSdJwt, loadAttestation, loadCredentials } from "@/functions";
import {
  createLogger,
  loadConfigWithHierarchy,
  loadJwks,
  partialCallbacks,
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

    this.fetchMetadataStep = issuanceConfig.fetchMetadata?.stepClass
      ? new issuanceConfig.fetchMetadata.stepClass(this.config, this.log)
      : new FetchMetadataDefaultStep(this.config, this.log);

    this.pushedAuthorizationRequestStep = issuanceConfig
      .pushedAuthorizationRequest?.stepClass
      ? new issuanceConfig.pushedAuthorizationRequest.stepClass(
          this.config,
          this.log,
        )
      : new PushedAuthorizationRequestDefaultStep(this.config, this.log);

    this.authorizeStep = issuanceConfig.authorize?.stepClass
      ? new issuanceConfig.authorize.stepClass(this.config, this.log)
      : new AuthorizeDefaultStep(this.config, this.log);

    this.tokenRequestStep = issuanceConfig.tokenRequest?.stepClass
      ? new issuanceConfig.tokenRequest.stepClass(this.config, this.log)
      : new TokenRequestDefaultStep(this.config, this.log);

    this.nonceRequestStep = issuanceConfig.nonceRequest?.stepClass
      ? new issuanceConfig.nonceRequest.stepClass(this.config, this.log)
      : new NonceRequestDefaultStep(this.config, this.log);

    this.credentialRequestStep = issuanceConfig.credentialRequest?.stepClass
      ? new issuanceConfig.credentialRequest.stepClass(this.config, this.log)
      : new CredentialRequestDefaultStep(this.config, this.log);
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async issuance(): Promise<{
    authorizeResponse: AuthorizeStepResponse;
    credentialResponse: CredentialRequestResponse;
    fetchMetadataResponse: FetchMetadataStepResponse;
    pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
    tokenResponse: TokenRequestResponse;
    nonceResponse: NonceRequestResponse;
    walletAttestationResponse: AttestationResponse;
  }> {
    try {
      this.log.info("Starting Test Issuance Flow...");

      const fetchMetadataOptions = this.issuanceConfig.fetchMetadata?.options;

      this.log.debug(
        "Fetch Metadata Options: ",
        JSON.stringify(fetchMetadataOptions),
      );
      const fetchMetadataResponse = await this.fetchMetadataStep.run({
        baseUrl: this.config.issuance.url,
        entityStatementClaimsSchema:
          fetchMetadataOptions?.entityStatementClaimsSchema ||
          itWalletEntityStatementClaimsSchema,
        wellKnownPath:
          fetchMetadataOptions?.wellKnownPath ||
          "/.well-known/openid-federation",
      });
      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.server.port}`;

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

      const clientAttestationDPoP = await createClientAttestationPopJwt({
        authorizationServer: entityStatementClaims.iss,
        callbacks,
        clientAttestation: walletAttestationResponse.attestation,
      });

      this.log.info("Sending Pushed Authorization Request...");

      const pushedAuthorizationRequestOptions =
        this.issuanceConfig.pushedAuthorizationRequest?.options;

      const pushedAuthorizationRequestResponse =
        await this.pushedAuthorizationRequestStep.run({
          clientId:
            pushedAuthorizationRequestOptions?.clientId ??
            walletAttestationResponse.unitKey.publicKey.kid,
          codeVerifier:
            pushedAuthorizationRequestOptions?.codeVerifier ??
            "example_code_verifier",
          credentialConfigurationId:
            this.issuanceConfig.credentialConfigurationId,
          popAttestation:
            pushedAuthorizationRequestOptions?.popAttestation ??
            clientAttestationDPoP,
          pushedAuthorizationRequestEndpoint:
            pushedAuthorizationRequestOptions?.pushedAuthorizationRequestEndpoint ??
            entityStatementClaims.metadata?.oauth_authorization_server
              ?.pushed_authorization_request_endpoint,
          walletAttestation:
            pushedAuthorizationRequestOptions?.walletAttestation ??
            walletAttestationResponse,
        });

      const authorizeOptions = this.issuanceConfig.authorize?.options;

      let personIdentificationData: Credential;

      try {
        const credentials = await loadCredentials(
          this.config.wallet.credentials_storage_path,
          ["dc_sd_jwt_PersonIdentificationData"],
          this.log.error,
        );

        if (credentials.dc_sd_jwt_PersonIdentificationData)
          personIdentificationData =
            credentials.dc_sd_jwt_PersonIdentificationData;
        else {
          this.log.error("missing pid: creating new one");
          throw new Error("missing pid: creating new one");
        }
      } catch {
        personIdentificationData = await createMockSdJwt(
          {
            iss: this.config.issuance.url,
            trustAnchorBaseUrl,
            trustAnchorJwksPath:
              this.config.trust.federation_trust_anchors_jwks_path,
          },
          this.config.wallet.backup_storage_path,
          this.config.wallet.credentials_storage_path,
        );
      }

      const authorizeResponse = await this.authorizeStep.run({
        authorizationEndpoint:
          authorizeOptions?.authorizationEndpoint ??
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.authorization_endpoint,
        baseUrl: authorizeOptions?.baseUrl ?? this.config.issuance.url,
        clientId:
          authorizeOptions?.clientId ??
          walletAttestationResponse.unitKey.publicKey.kid,
        credentials: [{
          credential: personIdentificationData.compact,
          keyPair: await loadJwks(this.config.wallet.backup_storage_path, "mock_pid_jwks")
        }],
        requestUri:
          authorizeOptions?.requestUri ??
          pushedAuthorizationRequestResponse.response?.request_uri,
        rpMetadata:
          authorizeOptions?.rpMetadata ??
          entityStatementClaims.metadata?.openid_credential_verifier,
        walletAttestation:
          pushedAuthorizationRequestOptions?.walletAttestation ??
          walletAttestationResponse,
      });

      const tokenRequestOptions = this.issuanceConfig.tokenRequest?.options;

      const accessTokenRequest: AccessTokenRequest =
        tokenRequestOptions?.accessTokenRequest ?? {
          code: authorizeResponse.response?.authorizeResponse?.code,
          code_verifier:
            pushedAuthorizationRequestOptions?.codeVerifier ??
            "example_code_verifier",
          grant_type: "authorization_code",
          redirect_uri: authorizeResponse.response?.requestObject?.response_uri,
        };
      const tokenResponse = await this.tokenRequestStep.run({
        accessTokenEndpoint:
          tokenRequestOptions?.accessTokenEndpoint ??
          entityStatementClaims.metadata?.oauth_authorization_server
            ?.token_endpoint,
        accessTokenRequest,
        popAttestation:
          tokenRequestOptions?.popAttestation ?? clientAttestationDPoP,
        walletAttestation:
          tokenRequestOptions?.walletAttestation ?? walletAttestationResponse,
      });

      const nonceRequestOptions = this.issuanceConfig.nonceRequest?.options;

      const nonceResponse = await this.nonceRequestStep.run({
        nonceEndpoint:
          nonceRequestOptions?.nonceEndpoint ??
          entityStatementClaims.metadata?.openid_credential_issuer
            ?.nonce_endpoint,
      });

      const nonce = nonceResponse.response?.nonce as
        | undefined
        | { c_nonce: string };
      const credentialRequestOptions =
        this.issuanceConfig.credentialRequest?.options;

      const credentialResponse = await this.credentialRequestStep.run({
        accessToken:
          credentialRequestOptions?.accessToken ??
          tokenResponse.response?.access_token ??
          "",
        baseUrl: credentialRequestOptions?.baseUrl ?? this.config.issuance.url,
        clientId:
          credentialRequestOptions?.clientId ??
          walletAttestationResponse.unitKey.publicKey.kid,
        credentialIdentifier:
          credentialRequestOptions?.credentialIdentifier ??
          this.issuanceConfig.credentialConfigurationId,
        credentialRequestEndpoint:
          credentialRequestOptions?.credentialRequestEndpoint ??
          entityStatementClaims.metadata?.openid_credential_issuer
            ?.credential_endpoint,
        nonce: credentialRequestOptions?.nonce ?? nonce?.c_nonce ?? "",
        walletAttestation:
          credentialRequestOptions?.walletAttestation ??
          walletAttestationResponse,
      });

      return {
        walletAttestationResponse,
        authorizeResponse,
        credentialResponse,
        fetchMetadataResponse,
        nonceResponse,
        pushedAuthorizationRequestResponse,
        tokenResponse,
      };
    } catch (e) {
      this.log.error("Error in Issuer Flow Tests!", e);
      throw e;
    }
  }
}
