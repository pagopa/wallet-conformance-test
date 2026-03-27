import { PresentationTestConfiguration } from "#/config";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { loadAttestation, loadCredentialsForPresentation } from "@/functions";
import { createLogger, loadConfigWithHierarchy } from "@/logic";
import {
  FetchMetadataVpDefaultStep,
  FetchMetadataVpStepResponse,
} from "@/step/presentation";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestStepResponse,
} from "@/step/presentation/authorization-request-step";
import {
  RedirectUriDefaultStep,
  RedirectUriStepResponse,
} from "@/step/presentation/redirect-uri-step";
import { assertStepSuccess } from "@/step/step-flow";
import {
  AttestationResponse,
  Config,
  CredentialWithKey,
  PresentationFlowResponse,
} from "@/types";

export class WalletPresentationOrchestratorFlow {
  private _authorizationRequestResult?: AuthorizationRequestStepResponse;
  private _fetchMetadataResult?: FetchMetadataVpStepResponse;
  private _redirectUriResult?: RedirectUriStepResponse;

  private authorizationRequestStep: AuthorizationRequestDefaultStep;
  private config: Config;
  private fetchMetadataStep: FetchMetadataVpDefaultStep;
  private log = createLogger();

  private presentationConfig: PresentationTestConfiguration;
  private redirectUriStep: RedirectUriDefaultStep;

  constructor(presentationConfig: PresentationTestConfiguration) {
    this.presentationConfig = presentationConfig;
    this.log = this.log.withTag(this.presentationConfig.name);

    this.config = loadConfigWithHierarchy();

    this.log.setLogOptions({
      fileFormat: this.config.logging.log_file_format,
      format: this.config.logging.log_format,
      level: this.config.logging.log_level,
      path: this.config.logging.log_file,
    });

    this.log.testSuite({
      profile: this.presentationConfig.name,
      target: this.config.presentation.authorize_request_url,
      title: this.presentationConfig.name,
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

  async presentation(): Promise<PresentationFlowResponse> {
    this.resetResponses();

    const TOTAL_STEPS = 3;
    try {
      const fetchMetadataResult = await this.fetchMetadataStep.run({
        baseUrl: this.prepareBaseUrl(),
      });
      this._fetchMetadataResult = fetchMetadataResult;
      this.log.flowStep(
        1,
        TOTAL_STEPS,
        "Fetch Metadata",
        fetchMetadataResult.success,
        fetchMetadataResult.durationMs ?? 0,
      );
      assertStepSuccess(fetchMetadataResult, "Fetch Metadata");

      const verifierMetadata =
        this.extractVerifierMetadata(fetchMetadataResult);

      const walletAttestation = await this.loadWalletAttestation();

      const credentials = await loadCredentialsForPresentation(
        this.config,
        this.log,
      );
      this.log.info(`Presenting ${credentials.length} local credentials`);

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
        success: true,
      };
    } catch (e) {
      this.log.error("Error in Presentation Flow Tests!", e);
      return {
        authorizationRequestResult: this._authorizationRequestResult,
        error: e instanceof Error ? e : new Error(String(e)),
        fetchMetadataResult: this._fetchMetadataResult,
        redirectUriResult: this._redirectUriResult,
        success: false,
      };
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
    this._authorizationRequestResult = authorizationRequestResponse;

    assertStepSuccess(authorizationRequestResponse, "Authorization Request");

    return authorizationRequestResponse;
  }

  private async executeRedirectUri(
    authorizationRequestResult: AuthorizationRequestStepResponse,
  ) {
    if (!authorizationRequestResult.response) {
      throw new Error("Authorization Request response is missing");
    }

    const redirectUriResult = await this.redirectUriStep.run({
      authorizationResponse:
        authorizationRequestResult.response.authorizationResponse,
      responseUri: authorizationRequestResult.response.responseUri,
    });
    this._redirectUriResult = redirectUriResult;
    assertStepSuccess(redirectUriResult, "Redirect URI");
    return redirectUriResult;
  }

  private extractVerifierMetadata(
    fetchMetadataResult: FetchMetadataVpStepResponse,
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

  private async loadWalletAttestation() {
    this.log.debug("Loading Wallet Attestation...");

    const walletAttestation = await loadAttestation({
      network: this.config.network,
      trust: this.config.trust,
      trustAnchor: this.config.trust_anchor,
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

  private resetResponses(): void {
    this._authorizationRequestResult = undefined;
    this._fetchMetadataResult = undefined;
    this._redirectUriResult = undefined;
  }
}
