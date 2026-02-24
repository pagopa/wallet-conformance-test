import { PresentationTestConfiguration } from "#/config";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { createMockSdJwt, loadAttestation, loadCredentials } from "@/functions";
import {
  buildJwksPath,
  createLogger,
  loadConfigWithHierarchy,
  loadJwks,
} from "@/logic";
import { FetchMetadataDefaultStep, FetchMetadataStepResponse } from "@/step";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestStepResponse,
  CredentialWithKey,
} from "@/step/presentation/authorization-request-step";
import {
  RedirectUriDefaultStep,
  RedirectUriStepResponse,
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

    this.log.debug("Setting Up Wallet conformance Tests - Presentation Flow");
    this.log.debug("Configuration Loaded from config.ini");

    this.log.debug(
      "Configuration Loaded:\n",
      JSON.stringify({
        credentialsDir: this.config.wallet.credentials_storage_path,
        maxRetries: this.config.network.max_retries,
        timeout: `${this.config.network.timeout}s`,
        userAgent: this.config.network.user_agent,
      }),
    );

    this.fetchMetadataStep = new presentationConfig.fetchMetadataStepClass(
      this.config,
      this.log,
    );
    this.authorizationRequestStep = new presentationConfig.authorizeStepClass(
      this.config,
      this.log,
    );
    this.redirectUriStep = new presentationConfig.redirectUriStepClass(
      this.config,
      this.log,
    );
  }

  getConfig(): Config {
    return this.config;
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async presentation(): Promise<{
    authorizationRequestResult: AuthorizationRequestStepResponse;
    fetchMetadataResult: FetchMetadataStepResponse;
    redirectUriResult: RedirectUriStepResponse;
  }> {
    const TOTAL_STEPS = 3;
    try {
      const fetchMetadataResult = await this.fetchMetadataStep.run({
        baseUrl: this.prepareBaseUrl(),
      });
      this.log.flowStep(
        1,
        TOTAL_STEPS,
        "Fetch Metadata",
        fetchMetadataResult.success,
        fetchMetadataResult.durationMs ?? 0,
      );

      const verifierMetadata =
        this.extractVerifierMetadata(fetchMetadataResult);

      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.trust_anchor.port}`;
      const walletAttestation =
        await this.loadWalletAttestation(trustAnchorBaseUrl);

      const credentialConfigIdentifiers = [
        "dc_sd_jwt_PersonIdentificationData",
      ];
      this.log.debug(
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
      this.log.flowStep(
        2,
        TOTAL_STEPS,
        "Authorization Request",
        authorizationRequestResult.success,
        authorizationRequestResult.durationMs ?? 0,
      );

      const redirectUriResult = await this.executeRedirectUri(
        authorizationRequestResult,
      );
      this.log.flowStep(
        3,
        TOTAL_STEPS,
        "Redirect URI",
        redirectUriResult.success,
        redirectUriResult.durationMs ?? 0,
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
    const authorizationRequestResponse =
      await this.authorizationRequestStep.run({
        credentials,
        verifierMetadata,
        walletAttestation,
      });

    if (!authorizationRequestResponse.response) {
      throw new Error(
        "Authorization Request response is missing or contains an error",
      );
    }

    return authorizationRequestResponse;
  }

  private async executeRedirectUri(
    authorizationRequestResult: AuthorizationRequestStepResponse,
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

  private async loadWalletAttestation(trustAnchorBaseUrl: string) {
    this.log.debug("Loading Wallet Attestation...");

    const walletAttestation = await loadAttestation({
      trustAnchorBaseUrl,
      trustAnchorJwksPath: this.config.trust.federation_trust_anchors_jwks_path,
      wallet: this.config.wallet,
    });

    this.log.debug("Wallet Attestation Loaded.");

    return walletAttestation;
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
      this.log.debug(
        `Using client_id from authorize_request_url as verifier baseUrl: ${baseUrl.href}`,
      );
      return baseUrl.href;
    }

    return this.config.presentation.verifier;
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
      buildJwksPath(credentialIdentifier),
    );

    return {
      credential: pid.compact,
      dpopJwk: privateKey,
    };
  }
}
