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
import { RunThroughAuthorizeVpContext } from "@/types/presentation-orchestrator-context";

export class WalletPresentationOrchestratorFlow {
  private _authorizationRequestResponse?: AuthorizationRequestStepResponse;
  private _fetchMetadataResponse?: FetchMetadataVpStepResponse;
  private _redirectUriResponse?: RedirectUriStepResponse;
  private _suitePrinted = false;

  private authorizationRequestStep: AuthorizationRequestDefaultStep;
  private config: Config;
  private fetchMetadataStep: FetchMetadataVpDefaultStep;
  private log = createLogger();

  private presentationConfig: PresentationTestConfiguration;
  private redirectUriStep: RedirectUriDefaultStep;
  private readonly TOTAL_STEPS = 3;

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

    try {
      const { authorizationRequestResponse, fetchMetadataResponse } =
        await this.runThroughAuthorize();

      const redirectUriResponse = await this.executeRedirectUri(
        authorizationRequestResponse,
      );
      this.log.flowStep(
        3,
        this.TOTAL_STEPS,
        "Redirect URI",
        redirectUriResponse.success,
        redirectUriResponse.durationMs ?? 0,
      );

      return {
        authorizationRequestResponse,
        fetchMetadataResponse,
        redirectUriResponse,
        success: true,
      };
    } catch (e) {
      this.log.error("Error in Presentation Flow Tests!", e);
      return {
        authorizationRequestResponse: this._authorizationRequestResponse,
        error: e instanceof Error ? e : new Error(String(e)),
        fetchMetadataResponse: this._fetchMetadataResponse,
        redirectUriResponse: this._redirectUriResponse,
        success: false,
      };
    }
  }

  async runThroughAuthorize(): Promise<RunThroughAuthorizeVpContext> {
    this.printTestSuiteOnce();

    const fetchMetadataResponse = await this.fetchMetadataStep.run({
      baseUrl: this.prepareBaseUrl(),
    });
    this._fetchMetadataResponse = fetchMetadataResponse;
    this.log.flowStep(
      1,
      this.TOTAL_STEPS,
      "Fetch Metadata",
      fetchMetadataResponse.success,
      fetchMetadataResponse.durationMs ?? 0,
    );
    assertStepSuccess(fetchMetadataResponse, "Fetch Metadata");

    const verifierMetadata = this.extractVerifierMetadata(
      fetchMetadataResponse,
    );

    const walletAttestationResponse = await this.loadWalletAttestation();

    const credentials = await loadCredentialsForPresentation(
      this.config,
      this.log,
    );
    this.log.info(`Presenting ${credentials.length} local credentials`);

    const authorizationRequestResponse = await this.executeAuthorizationRequest(
      credentials,
      verifierMetadata,
      walletAttestationResponse,
    );
    this.log.flowStep(
      2,
      this.TOTAL_STEPS,
      "Authorization Request",
      authorizationRequestResponse.success,
      authorizationRequestResponse.durationMs ?? 0,
    );

    return {
      authorizationRequestResponse,
      credentials,
      fetchMetadataResponse,
      verifierMetadata,
      walletAttestationResponse,
    };
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
    this._authorizationRequestResponse = authorizationRequestResponse;

    assertStepSuccess(authorizationRequestResponse, "Authorization Request");

    return authorizationRequestResponse;
  }

  private async executeRedirectUri(
    authorizationRequestResponse: AuthorizationRequestStepResponse,
  ) {
    if (!authorizationRequestResponse.response) {
      throw new Error("Authorization Request response is missing");
    }

    const redirectUriResponse = await this.redirectUriStep.run({
      authorizationResponse:
        authorizationRequestResponse.response.authorizationResponse,
      responseUri: authorizationRequestResponse.response.responseUri,
    });
    this._redirectUriResponse = redirectUriResponse;
    assertStepSuccess(redirectUriResponse, "Redirect URI");
    return redirectUriResponse;
  }

  private extractVerifierMetadata(
    fetchMetadataResponse: FetchMetadataVpStepResponse,
  ) {
    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;

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

  private printTestSuiteOnce(): void {
    if (this._suitePrinted) return;
    this._suitePrinted = true;
    this.log.testSuite({
      profile: this.presentationConfig.name,
      specsVersion: this.config.wallet.wallet_version,
      target: this.config.presentation.authorize_request_url,
      title: this.presentationConfig.name,
    });

    this.log.debug("Setting Up Wallet conformance Tests - Presentation Flow");
    this.log.debug(
      "Configuration Loaded (Hierarchy: CLI options > Custom INI > Default INI)",
    );

    this.log.debug(
      "Configuration Loaded:\n",
      JSON.stringify({
        credentialsDir: this.config.wallet.credentials_storage_path,
        maxRetries: this.config.network.max_retries,
        timeout: `${this.config.network.timeout}s`,
        userAgent: this.config.network.user_agent,
      }),
    );
  }

  private resetResponses(): void {
    this._authorizationRequestResponse = undefined;
    this._fetchMetadataResponse = undefined;
    this._redirectUriResponse = undefined;
  }
}
