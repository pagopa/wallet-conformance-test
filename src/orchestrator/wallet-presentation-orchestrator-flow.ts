import { PresentationTestConfiguration } from "#/config";
import {
  ItWalletCredentialVerifierMetadata,
  itWalletEntityStatementClaimsSchema,
} from "@pagopa/io-wallet-oid-federation";

import { createMockSdJwt, loadAttestation, loadCredentials } from "@/functions";
import { createLogger, loadConfigWithHierarchy, loadJwks } from "@/logic";
import {
  FetchMetadataDefaultStep,
  FetchMetadataStepResponse,
} from "@/step/fetch-metadata-step";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestStepResult,
  CredentialWithKey,
} from "@/step/presentation/authorization-request-step";
import {
  RedirectUriDefaultStep,
  RedirectUriStepResult,
} from "@/step/presentation/redirect-uri-step";
import { AttestationResponse, Config } from "@/types";

export class WalletPresentationOrchestratorFlow {
  private authorizationRequestStep: AuthorizationRequestDefaultStep;
  private config: Config;
  private fetchMetadataStep: FetchMetadataDefaultStep;
  private log = createLogger();

  private presentationConfig: PresentationTestConfiguration;
  private redirectUriStep: RedirectUriDefaultStep;

  constructor(presentationConfig: PresentationTestConfiguration) {
    this.presentationConfig = presentationConfig;
    this.log = this.log.withTag(this.presentationConfig.name);

    this.config = loadConfigWithHierarchy();

    this.log.setLogOptions({
      format: this.config.logging.log_format,
      level: this.config.logging.log_level,
      path: this.config.logging.log_file,
    });

    this.log.info("Setting Up Wallet conformance Tests - Presentation Flow");
    this.log.info("Configuration Loaded from config.ini");

    this.log.info(
      "Configuration Loaded:\n",
      JSON.stringify({
        credentialsDir: this.config.wallet.credentials_storage_path,
        maxRetries: this.config.network.max_retries,
        timeout: `${this.config.network.timeout}s`,
        userAgent: this.config.network.user_agent,
      }),
    );

    this.fetchMetadataStep = presentationConfig.fetchMetadata?.stepClass
      ? new presentationConfig.fetchMetadata.stepClass(this.config, this.log)
      : new FetchMetadataDefaultStep(this.config, this.log);

    this.authorizationRequestStep = presentationConfig.authorize?.stepClass
      ? new presentationConfig.authorize.stepClass(this.config, this.log)
      : new AuthorizationRequestDefaultStep(this.config, this.log);

    this.redirectUriStep = presentationConfig.redirectUri?.stepClass
      ? new presentationConfig.redirectUri.stepClass(this.config, this.log)
      : new RedirectUriDefaultStep(this.config, this.log);
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async presentation(): Promise<{
    authorizationRequestResult: AuthorizationRequestStepResult;
    fetchMetadataResult: FetchMetadataStepResponse;
    redirectUriResult: RedirectUriStepResult;
  }> {
    try {
      this.log.info("Starting Test Presentation Flow...");

      const fetchMetadataResult = await this.fetchVerifierMetadata();
      const verifierMetadata =
        this.extractVerifierMetadata(fetchMetadataResult);

      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.trust_anchor.port}`;
      const walletAttestation =
        await this.loadWalletAttestation(trustAnchorBaseUrl);

      const credentialConfigIdentifiers = [
        "dc_sd_jwt_PersonIdentificationData",
      ];
      this.log.info(
        "Presenting local credentials:",
        credentialConfigIdentifiers,
      );

      const credentials: CredentialWithKey[] = await Promise.all(
        credentialConfigIdentifiers.map(
          async (credentialConfigIdentifier) =>
            await this.prepareCredential(
              trustAnchorBaseUrl,
              credentialConfigIdentifier,
            ),
        ),
      );

      const authorizationRequestResult = await this.executeAuthorizationRequest(
        credentials,
        verifierMetadata,
        walletAttestation,
      );

      const redirectUriResult = await this.executeRedirectUri(
        authorizationRequestResult,
      );

      return {
        authorizationRequestResult,
        fetchMetadataResult,
        redirectUriResult,
      };
    } catch (e) {
      this.log.error("Error in Presentation Flow Tests!", e);
      throw e;
    }
  }

  private async executeAuthorizationRequest(
    credentials: CredentialWithKey[],
    verifierMetadata: ItWalletCredentialVerifierMetadata,
    walletAttestation: AttestationResponse,
  ) {
    const authorizationOptions = this.presentationConfig.authorize?.options;

    const authorizationRequestResponse =
      await this.authorizationRequestStep.run({
        authorizeRequestUrl:
          authorizationOptions?.authorizeRequestUrl ||
          this.config.presentation.authorize_request_url,
        credentials,
        verifierMetadata:
          authorizationOptions?.verifierMetadata || verifierMetadata,
        walletAttestation:
          authorizationOptions?.walletAttestation || walletAttestation,
      });

    if (!authorizationRequestResponse.response) {
      throw new Error("Authorization Request response is missing or contains an error");
    }

    return authorizationRequestResponse;
  }

  private async executeRedirectUri(
    authorizationRequestResult: AuthorizationRequestStepResult,
  ) {
    if (!authorizationRequestResult.response) {
      throw new Error("Authorization Request response is missing");
    }

    return await this.redirectUriStep.run({
      authorizationResponse:
        authorizationRequestResult.response.authorizationResponse,
      responseUri: authorizationRequestResult.response.responseUri,
    });
  }

  private extractVerifierMetadata(
    fetchMetadataResult: FetchMetadataStepResponse,
  ) {
    const entityStatementClaims =
      fetchMetadataResult.response?.entityStatementClaims;

    if (!entityStatementClaims) {
      throw new Error("Entity Statement Claims not found in response");
    }

    const rpMetadata =
      entityStatementClaims.metadata.openid_credential_verifier;

    if (!rpMetadata) {
      throw new Error(
        "Verifier metadata (openid_credential_verifier) not found",
      );
    }

    return rpMetadata;
  }

  private async fetchVerifierMetadata(): Promise<FetchMetadataStepResponse> {
    const fetchMetadataOptions = this.presentationConfig.fetchMetadata?.options;

    this.log.debug(
      "Fetch Metadata Options: ",
      JSON.stringify(fetchMetadataOptions),
    );

    const baseUrl = this.prepareBaseUrl();

    return await this.fetchMetadataStep.run({
      baseUrl: fetchMetadataOptions?.baseUrl || baseUrl,
      entityStatementClaimsSchema:
        fetchMetadataOptions?.entityStatementClaimsSchema ||
        itWalletEntityStatementClaimsSchema,
      wellKnownPath:
        fetchMetadataOptions?.wellKnownPath || "/.well-known/openid-federation",
    });
  }

  private async loadWalletAttestation(trustAnchorBaseUrl: string) {
    this.log.info("Loading Wallet Attestation...");

    const walletAttestation = await loadAttestation({
      trustAnchorBaseUrl,
      trustAnchorJwksPath: this.config.trust.federation_trust_anchors_jwks_path,
      wallet: this.config.wallet,
    });

    this.log.info("Wallet Attestation Loaded.");

    return walletAttestation;
  }

  private async prepareCredential(
    trustAnchorBaseUrl: string,
    credentialIdentifier: string,
  ): Promise<CredentialWithKey> {
    const credentials = await loadCredentials(
      this.config.wallet.credentials_storage_path,
      [credentialIdentifier],
      this.log.debug,
    );

    const pid = credentials[credentialIdentifier]
      ? credentials[credentialIdentifier]
      : await createMockSdJwt(
          {
            iss: "https://issuer.example.com",
            trustAnchorBaseUrl,
            trustAnchorJwksPath:
              this.config.trust.federation_trust_anchors_jwks_path,
          },
          this.config.wallet.backup_storage_path,
          this.config.wallet.credentials_storage_path,
        );

    const { privateKey } = await loadJwks(
      this.config.wallet.backup_storage_path,
      `${credentialIdentifier}_jwks`,
    );

    return {
      credential: pid.compact,
      dpopJwk: privateKey,
    };
  }

  private prepareBaseUrl(): string {
    if (!this.config.presentation.verifier) {
      const authorizeUrl = new URL(
        this.config.presentation.authorize_request_url,
      );
      const clientId = authorizeUrl.searchParams.get("client_id");

      if (!clientId) {
        throw new Error(
          "client_id parameter not found in authorize_request_url and verifier not configured",
        );
      }

      const baseUrl = new URL(clientId);
      this.log.info(
        `Using client_id from authorize_request_url as verifier baseUrl: ${baseUrl.href}`,
      );
      return baseUrl.href;
    }

    return this.config.presentation.verifier;
  }
}
