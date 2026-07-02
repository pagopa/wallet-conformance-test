import { IssuerTestConfiguration } from "#/config";
import {
  AccessTokenRequest,
  createClientAttestationPopJwt,
} from "@pagopa/io-wallet-oauth2";
import { resolveCredentialOffer } from "@pagopa/io-wallet-oid4vci";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";
import { randomUUID } from "node:crypto";

import { loadAttestation, loadCredentialsForPresentation } from "@/functions";
import {
  createLogger,
  loadConfigWithHierarchy,
  partialCallbacks,
  saveCredentialToDisk,
  signJwtCallback,
} from "@/logic";
import { getCallbackRedirectUri } from "@/logic/constants";
import {
  CredentialConfigurationError,
  DeferredIssuancePreconditionError,
  IssuerMetadataError,
  OrchestratorError,
  ReissuancePreconditionError,
  StepOutputError,
} from "@/orchestrator/errors";
import {
  AuthorizeDefaultStep,
  AuthorizeStepResponse,
  CredentialRequestDefaultStep,
  CredentialRequestResponse,
  DeferredCredentialRequestDefaultStep,
  DeferredCredentialRequestResponse,
  FetchMetadataDefaultStep,
  FetchMetadataStepResponse,
  NonceRequestDefaultStep,
  NonceRequestResponse,
  NotificationRequestDefaultStep,
  NotificationRequestResponse,
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestResponse,
  TokenRequestDefaultStep,
  TokenRequestResponse,
} from "@/step/issuance";
import { assertStepSuccess } from "@/step/step-flow";
import {
  AttestationResponse,
  Config,
  DeferredIssuanceFlowResponse,
  IssuanceFlowResponse,
  KeyPair,
  ReissuanceFlowResponse,
  RunThroughAuthorizeContext,
  RunThroughParContext,
  RunThroughRefreshTokenContext,
  RunThroughTokenContext,
} from "@/types";

export class WalletIssuanceOrchestratorFlow {
  private _authorizeResponse?: AuthorizeStepResponse;
  private _credentialResponse?: CredentialRequestResponse;
  private _deferredCredentialResponse?: DeferredCredentialRequestResponse;
  private _fetchMetadataResponse?: FetchMetadataStepResponse;
  private _nonceResponse?: NonceRequestResponse;
  private _notificationRequestResponse?: NotificationRequestResponse;
  private _pushedAuthorizationRequestResponse?: PushedAuthorizationRequestResponse;
  private _suitePrinted = false;
  private _tokenResponse?: TokenRequestResponse;

  private _walletAttestationResponse?: AttestationResponse;

  private authorizeStep: AuthorizeDefaultStep;
  private config: Config;
  private credentialRequestStep: CredentialRequestDefaultStep;
  private deferredCredentialRequestStep: DeferredCredentialRequestDefaultStep;
  private fetchMetadataStep: FetchMetadataDefaultStep;
  private readonly ISSUANCE_WITH_DELETED_TOTAL_STEPS = 7;
  private issuanceConfig: IssuerTestConfiguration;
  private log = createLogger();
  private nonceRequestStep: NonceRequestDefaultStep;

  private notificationRequestStep: NotificationRequestDefaultStep;
  private pushedAuthorizationRequestStep: PushedAuthorizationRequestDefaultStep;
  private sdkConfig: IoWalletSdkConfig;
  private tokenRequestStep: TokenRequestDefaultStep;
  private readonly TOTAL_STEPS = 6;

  constructor(issuanceConfig: IssuerTestConfiguration) {
    this.issuanceConfig = issuanceConfig;
    this.log = this.log.withTag(this.issuanceConfig.name);

    this.config = loadConfigWithHierarchy();
    this.sdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: this.config.wallet.wallet_version,
    });

    this.log.setLogOptions({
      fileFormat: this.config.logging.log_file_format,
      format: this.config.logging.log_format,
      level: this.config.logging.log_level,
      path: this.config.logging.log_file,
    });

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

    this.notificationRequestStep =
      new issuanceConfig.notificationRequestStepClass(this.config, this.log);
    this.deferredCredentialRequestStep =
      new DeferredCredentialRequestDefaultStep(this.config, this.log);
  }

  /**
   * Executes the Deferred Issuance Flow.
   *
   * Requires both `refresh_token_deferred` and `transaction_id` to be set in
   * the issuance configuration (or passed via CLI / env). Fails fast without
   * contacting any remote endpoint when either prerequisite is missing.
   *
   * The flow:
   *   1. Fetch issuer metadata.
   *   2. Load wallet attestation.
   *   3. Request a new access token using the deferred refresh token.
   *   4. POST to `deferred_credential_endpoint` with the `transaction_id`.
   */
  async deferred(): Promise<DeferredIssuanceFlowResponse> {
    this.resetResponses();

    try {
      const refreshTokenDeferred = this.config.issuance.refresh_token_deferred;
      const transactionId = this.config.issuance.transaction_id_deferred;

      if (!refreshTokenDeferred || !transactionId) {
        throw new DeferredIssuancePreconditionError();
      }

      const {
        dPoPKey,
        fetchMetadataResponse,
        tokenResponse,
        walletAttestationResponse,
      } = await this.runThroughRefreshToken(refreshTokenDeferred);

      const accessToken = tokenResponse.response?.access_token;
      if (!accessToken)
        throw new StepOutputError(TokenRequestDefaultStep.tag, "access_token");

      const deferredCredentialResponse =
        await this.requestDeferredCredentialWithToken({
          accessToken,
          dPoPKey,
          fetchMetadataResponse,
          transactionId,
        });

      return {
        deferredCredentialResponse,
        fetchMetadataResponse,
        success: true,
        tokenResponse,
        walletAttestationResponse,
      };
    } catch (e) {
      this.log.error("Error in Deferred Issuance Flow!", e);
      return {
        deferredCredentialResponse: this._deferredCredentialResponse,
        error: e instanceof Error ? e : new Error(String(e)),
        fetchMetadataResponse: this._fetchMetadataResponse,
        success: false,
        tokenResponse: this._tokenResponse,
        walletAttestationResponse: this._walletAttestationResponse,
      };
    }
  }

  async findCredentialConfig(): Promise<{
    credentialConfigurationIds: string[];
    credentialIssuer: string;
  }> {
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
        config: this.sdkConfig,
        credentialOffer: this.config.issuance.credential_offer_uri,
      });
      this.log.debug(
        "Received Credential Offer:\n",
        JSON.stringify(credentialOffer),
      );

      credentialIssuer = credentialOffer.credential_issuer;
      credentialConfigurationIds = credentialOffer.credential_configuration_ids;

      if (credentialConfigurationIds.length === 0)
        throw new OrchestratorError(
          "Cannot proceed: The credential offer returned no credential configuration IDs",
          "CREDENTIAL_CONFIGURATION_ID_UNRESOLVED",
        );
    } else {
      this.log.debug(
        "Missing Credential Offer URI: using Credential Issuer and Credential ID from configuration",
      );

      credentialIssuer = this.config.issuance.url;
      credentialConfigurationIds = [
        this.issuanceConfig.credentialConfigurationId,
      ];

      if (credentialConfigurationIds.length === 0)
        throw new OrchestratorError(
          "No credential configuration ID could be resolved. " +
            "Neither the test configuration nor the credential offer provided one. " +
            "Set 'credential_types[]' in config.ini or pass --credential-types <types>.",
          "CREDENTIAL_CONFIGURATION_ID_UNRESOLVED",
        );
    }
    return { credentialConfigurationIds, credentialIssuer };
  }

  getConfig(): Config {
    return this.config;
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async issuance(): Promise<IssuanceFlowResponse> {
    this.resetResponses();

    try {
      const {
        authorizeResponse,
        credentialIssuer,
        dPoPKey,
        fetchMetadataResponse,
        pushedAuthorizationRequestResponse,
        tokenResponse,
        walletAttestationResponse,
      } = await this.runThroughToken();

      const accessToken = tokenResponse.response?.access_token;
      if (!accessToken)
        throw new StepOutputError(TokenRequestDefaultStep.tag, "access_token");

      const { credentialResponse, nonceResponse } =
        await this.requestCredentialWithToken({
          accessToken,
          credentialIssuer,
          dPoPKey,
          fetchMetadataResponse,
          walletAttestationResponse,
        });

      await this.sendCredentialDeletedNotificationIfNeeded({
        accessToken,
        credentialResponse,
        dPoPKey,
        fetchMetadataResponse,
      });

      return {
        authorizeResponse,
        credentialResponse,
        fetchMetadataResponse,
        nonceResponse,
        notificationRequestResponse: this._notificationRequestResponse,
        pushedAuthorizationRequestResponse,
        success: true,
        tokenResponse,
        walletAttestationResponse,
      };
    } catch (e) {
      this.log.error("Error in Issuer Flow Tests!", e);
      return {
        authorizeResponse: this._authorizeResponse,
        credentialResponse: this._credentialResponse,
        error: e instanceof Error ? e : new Error(String(e)),
        fetchMetadataResponse: this._fetchMetadataResponse,
        nonceResponse: this._nonceResponse,
        notificationRequestResponse: this._notificationRequestResponse,
        pushedAuthorizationRequestResponse:
          this._pushedAuthorizationRequestResponse,
        success: false,
        tokenResponse: this._tokenResponse,
        walletAttestationResponse: this._walletAttestationResponse,
      };
    }
  }

  async reissuance(): Promise<ReissuanceFlowResponse> {
    this.resetResponses();

    try {
      const refreshToken = this.config.issuance.refresh_token;
      if (!refreshToken) {
        throw new ReissuancePreconditionError();
      }

      const {
        credentialIssuer,
        dPoPKey,
        fetchMetadataResponse,
        tokenResponse,
        walletAttestationResponse,
      } = await this.runThroughRefreshToken(refreshToken);

      const accessToken = tokenResponse.response?.access_token;
      if (!accessToken)
        throw new StepOutputError(TokenRequestDefaultStep.tag, "access_token");

      const { credentialResponse, nonceResponse } =
        await this.requestCredentialWithToken({
          accessToken,
          credentialIssuer,
          dPoPKey,
          fetchMetadataResponse,
          walletAttestationResponse,
        });

      return {
        credentialResponse,
        fetchMetadataResponse,
        nonceResponse,
        success: true,
        tokenResponse,
        walletAttestationResponse,
      };
    } catch (e) {
      this.log.error("Error in Re-Issuance Flow!", e);
      return {
        credentialResponse: this._credentialResponse,
        error: e instanceof Error ? e : new Error(String(e)),
        fetchMetadataResponse: this._fetchMetadataResponse,
        nonceResponse: this._nonceResponse,
        success: false,
        tokenResponse: this._tokenResponse,
        walletAttestationResponse: this._walletAttestationResponse,
      };
    }
  }

  /**
   * Executes the full issuance flow from the beginning through the authorize step.
   * Each call starts a new flow from step 1.
   * Warning: Do NOT call this after runThroughPar() on the same instance — both
   * methods re-execute from scratch and will cause duplicate PAR requests.
   */
  async runThroughAuthorize(): Promise<RunThroughAuthorizeContext> {
    const parCtx = await this.runThroughPar();
    const {
      credentialIssuer,
      fetchMetadataResponse,
      pushedAuthorizationRequestResponse,
      walletAttestationResponse,
    } = parCtx;
    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;

    this.log.debug(
      `Code Verifier generated for Pushed Authorization '${pushedAuthorizationRequestResponse.response?.codeVerifier}'`,
    );

    const authorizationEndpoint =
      entityStatementClaims.metadata?.oauth_authorization_server
        ?.authorization_endpoint;

    if (!authorizationEndpoint)
      throw new IssuerMetadataError(
        "authorization_endpoint",
        "oauth_authorization_server",
        "Authorization Request",
      );

    this.log.info("Loading credentials...");

    const credentials = await loadCredentialsForPresentation(
      this.config,
      this.log,
    );
    const authorizeResponse = await this.authorizeStep.run({
      authorizationEndpoint:
        entityStatementClaims.metadata?.oauth_authorization_server
          ?.authorization_endpoint,
      baseUrl: credentialIssuer,
      clientId: walletAttestationResponse.unitKey.publicKey.kid,
      credentialIdentifier: this.issuanceConfig.credentialConfigurationId,
      credentials,
      requestUri: pushedAuthorizationRequestResponse.response?.request_uri,
      rpMetadata: entityStatementClaims.metadata?.openid_credential_verifier,
      walletAttestation: walletAttestationResponse,
    });
    this._authorizeResponse = authorizeResponse;
    this.log.flowStep(
      3,
      this.TOTAL_STEPS,
      "Authorization",
      authorizeResponse.success,
      authorizeResponse.durationMs ?? 0,
    );
    assertStepSuccess(authorizeResponse, "Authorization");

    return { ...parCtx, authorizationEndpoint, authorizeResponse };
  }

  /**
   * Executes the full issuance flow from the beginning through the PAR step.
   * Each call starts a new flow from step 1.
   * Warning: Do NOT call this and then runThroughToken() on the same instance —
   * both methods re-execute from scratch and will cause duplicate PAR requests.
   */
  async runThroughPar(): Promise<RunThroughParContext> {
    this.printTestSuiteOnce();
    this.log.info("Starting Test Issuance Flow...");

    const { credentialConfigurationIds, credentialIssuer } =
      await this.findCredentialConfig();

    this.log.info(
      `Requesting credentials ${JSON.stringify(credentialConfigurationIds)} from issuer ${credentialIssuer}`,
    );

    const fetchMetadataResponse = await this.fetchMetadataStep.run({
      baseUrl: credentialIssuer,
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

    const walletAttestationResponse = await loadAttestation({
      trust: this.config.trust,
      trustAnchor: this.config.trust_anchor,
      wallet: this.config.wallet,
    });
    this._walletAttestationResponse = walletAttestationResponse;

    const callbacks = {
      ...partialCallbacks,
      signJwt: signJwtCallback([walletAttestationResponse.unitKey.privateKey]),
    };

    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;
    if (!entityStatementClaims) {
      throw new OrchestratorError(
        "Fetch Metadata step returned no entity statement claims. " +
          "Verify the issuer URL is reachable and returns a valid " +
          "OpenID Federation Entity Statement.",
        "ENTITY_STATEMENT_CLAIMS_MISSING",
      );
    }

    // Validate credentialConfigurationId is supported by the issuer
    const credentialConfigsSupported =
      entityStatementClaims.metadata?.openid_credential_issuer
        ?.credential_configurations_supported;

    if (credentialConfigsSupported) {
      const supportedIds = Object.keys(credentialConfigsSupported);
      const requestedId = this.issuanceConfig.credentialConfigurationId;

      if (!supportedIds.includes(requestedId)) {
        throw new CredentialConfigurationError(
          requestedId,
          "unsupported_by_issuer",
          supportedIds,
        );
      }

      if (
        this.config.issuance.credential_offer_uri &&
        !credentialConfigurationIds.includes(requestedId)
      ) {
        throw new CredentialConfigurationError(
          requestedId,
          "not_in_offer",
          credentialConfigurationIds,
        );
      }
    } else
      this.log.warn(
        "Skipping credentialConfigurationId validation: " +
          "'credential_configurations_supported' is absent from issuer metadata. " +
          "This may indicate a non-conformant issuer or an incomplete metadata endpoint.",
      );

    const popAttestation = await createClientAttestationPopJwt({
      authorizationServer: credentialIssuer,
      callbacks,
      clientAttestation: walletAttestationResponse.attestation,
      config: new IoWalletSdkConfig({
        itWalletSpecsVersion: this.config.wallet.wallet_version,
      }),
      jti: randomUUID(),
    });

    const pushedAuthorizationRequestEndpoint =
      entityStatementClaims.metadata?.oauth_authorization_server
        ?.pushed_authorization_request_endpoint;

    if (!pushedAuthorizationRequestEndpoint) {
      throw new IssuerMetadataError(
        "pushed_authorization_request_endpoint",
        "oauth_authorization_server",
        "Pushed Authorization Request",
      );
    }

    const pushedAuthorizationRequestResponse =
      await this.pushedAuthorizationRequestStep.run({
        baseUrl: credentialIssuer,
        credentialConfigurationIds,
        popAttestation,
        pushedAuthorizationRequestEndpoint,
        walletAttestation: walletAttestationResponse,
      });
    this._pushedAuthorizationRequestResponse =
      pushedAuthorizationRequestResponse;

    this.log.flowStep(
      2,
      this.TOTAL_STEPS,
      "Pushed Authorization Request",
      pushedAuthorizationRequestResponse.success,
      pushedAuthorizationRequestResponse.durationMs ?? 0,
    );
    assertStepSuccess(
      pushedAuthorizationRequestResponse,
      "Pushed Authorization Request",
    );

    return {
      authorizationServer: entityStatementClaims.iss,
      credentialIssuer,
      fetchMetadataResponse,
      popAttestation,
      pushedAuthorizationRequestEndpoint,
      pushedAuthorizationRequestResponse,
      walletAttestationResponse,
    };
  }

  /**
   * Executes the full issuance flow from the beginning through the token request step.
   * Each call starts a new flow from step 1.
   * Warning: Do NOT call this after runThroughPar() or runThroughAuthorize() on the
   * same instance — all methods re-execute from scratch and will cause duplicate requests.
   */
  async runThroughToken(): Promise<RunThroughTokenContext> {
    const authorizeCtx = await this.runThroughAuthorize();

    const {
      authorizeResponse,
      fetchMetadataResponse,
      popAttestation,
      pushedAuthorizationRequestResponse,
      walletAttestationResponse,
    } = authorizeCtx;

    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;

    if (
      !authorizeResponse.response ||
      !authorizeResponse.response.authorizeResponse
    ) {
      throw new OrchestratorError(
        "Authorization step returned no response object. " +
          "The authorization redirect may not have been captured. " +
          "Verify that the redirect_uri is reachable and that the " +
          "authorize step completed successfully.",
        "AUTHORIZATION_RESPONSE_MISSING",
      );
    }

    const code = authorizeResponse.response.authorizeResponse?.code;
    if (!code) throw new StepOutputError("AUTHORIZE", "code");

    const code_verifier =
      pushedAuthorizationRequestResponse.response?.codeVerifier;
    if (!code_verifier)
      throw new StepOutputError(
        "PUSHED_AUTHORIZATION_REQUEST",
        "code_verifier",
      );

    const accessTokenRequest: AccessTokenRequest = {
      code: authorizeResponse.response.authorizeResponse.code,
      code_verifier,
      grant_type: "authorization_code",
      redirect_uri: getCallbackRedirectUri(this.config.issuance.callback_port),
    };

    const tokenResponse = await this.tokenRequestStep.run({
      accessTokenEndpoint:
        entityStatementClaims.metadata?.oauth_authorization_server
          ?.token_endpoint,
      accessTokenRequest,
      popAttestation,
      walletAttestation: walletAttestationResponse,
    });
    this._tokenResponse = tokenResponse;
    this.log.flowStep(
      4,
      this.TOTAL_STEPS,
      "Token Request",
      tokenResponse.success,
      tokenResponse.durationMs ?? 0,
    );
    assertStepSuccess(tokenResponse, "Token Request");

    const dPoPKey = tokenResponse.response?.dPoPKey;
    if (!dPoPKey) throw new StepOutputError("TOKEN_REQUEST", "dPoPKey");

    return { ...authorizeCtx, dPoPKey, tokenResponse };
  }

  private getCredentialDeletedNotificationEndpoint(
    fetchMetadataResponse: FetchMetadataStepResponse,
  ): string {
    const notificationEndpoint =
      fetchMetadataResponse.response?.entityStatementClaims.metadata
        ?.openid_credential_issuer?.notification_endpoint;

    if (!notificationEndpoint) {
      throw new IssuerMetadataError(
        "notification_endpoint",
        "openid_credential_issuer",
        "Credential Deleted Notification",
      );
    }

    return notificationEndpoint;
  }

  private printTestSuiteOnce(): void {
    if (this._suitePrinted) return;
    this._suitePrinted = true;
    this.log.testSuite({
      profile: this.issuanceConfig.credentialConfigurationId,
      specsVersion: this.config.wallet.wallet_version,
      target: this.config.issuance.url,
      title: this.issuanceConfig.name,
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
  }

  /**
   * Performs the shared Nonce Request → Credential Request → optional save-to-disk
   * sequence used by both issuance() and reissuance().
   */
  private async requestCredentialWithToken({
    accessToken,
    credentialIssuer,
    dPoPKey,
    fetchMetadataResponse,
    walletAttestationResponse,
  }: {
    accessToken: string;
    credentialIssuer: string;
    dPoPKey: KeyPair;
    fetchMetadataResponse: FetchMetadataStepResponse;
    walletAttestationResponse: AttestationResponse;
  }): Promise<{
    credentialResponse: CredentialRequestResponse;
    nonceResponse: NonceRequestResponse;
  }> {
    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;

    const nonceResponse = await this.nonceRequestStep.run({
      nonceEndpoint:
        entityStatementClaims.metadata?.openid_credential_issuer
          ?.nonce_endpoint,
    });
    this._nonceResponse = nonceResponse;
    this.log.flowStep(
      5,
      this.TOTAL_STEPS,
      "Nonce Request",
      nonceResponse.success,
      nonceResponse.durationMs ?? 0,
    );
    assertStepSuccess(nonceResponse, "Nonce Request");

    const nonce = nonceResponse.response?.nonce as
      | undefined
      | { c_nonce: string };
    if (!nonce)
      throw new StepOutputError(NonceRequestDefaultStep.tag, "c_nonce");

    const credentialResponse = await this.credentialRequestStep.run({
      accessToken,
      clientId: walletAttestationResponse.unitKey.publicKey.kid,
      credentialIdentifier: this.issuanceConfig.credentialConfigurationId,
      credentialIssuer: credentialIssuer,
      credentialRequestEndpoint:
        entityStatementClaims.metadata?.openid_credential_issuer
          ?.credential_endpoint,
      dPoPKey,
      nonce: nonce.c_nonce,
      walletAttestation: walletAttestationResponse,
    });
    this._credentialResponse = credentialResponse;
    this.log.flowStep(
      6,
      this.TOTAL_STEPS,
      "Credential Request",
      credentialResponse.success,
      credentialResponse.durationMs ?? 0,
    );
    assertStepSuccess(credentialResponse, "Credential Request");

    // Save credential to disk if configured
    // Currently, only the first credential is saved because we support requesting one at a time
    const firstCredential = credentialResponse.response?.credentials?.[0];
    if (this.config.issuance.save_credential && firstCredential?.credential) {
      const savedPath = saveCredentialToDisk(
        this.config.wallet.credentials_storage_path,
        this.issuanceConfig.credentialConfigurationId,
        firstCredential.credential,
        this.config.wallet.wallet_version,
      );
      if (savedPath) {
        this.log.info(`Credential saved to disk: ${savedPath}`);
      } else {
        this.log.error("Failed to save credential to disk");
      }
    }

    return { credentialResponse, nonceResponse };
  }

  /**
   * Sends a Deferred Credential Request to the deferred_credential_endpoint using
   * the access token and transaction_id. Saves the credential to disk if configured.
   */
  private async requestDeferredCredentialWithToken({
    accessToken,
    dPoPKey,
    fetchMetadataResponse,
    transactionId,
  }: {
    accessToken: string;
    dPoPKey: KeyPair;
    fetchMetadataResponse: FetchMetadataStepResponse;
    transactionId: string;
  }): Promise<DeferredCredentialRequestResponse> {
    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;

    const deferredCredentialEndpoint =
      entityStatementClaims?.metadata?.openid_credential_issuer
        ?.deferred_credential_endpoint;
    if (!deferredCredentialEndpoint) {
      throw new IssuerMetadataError(
        "deferred_credential_endpoint",
        "openid_credential_issuer",
        "Deferred Credential Request",
      );
    }

    const deferredCredentialResponse =
      await this.deferredCredentialRequestStep.run({
        accessToken,
        deferredCredentialEndpoint,
        dPoPKey,
        transactionId,
      });
    this._deferredCredentialResponse = deferredCredentialResponse;
    this.log.flowStep(
      5,
      this.TOTAL_STEPS,
      "Deferred Credential Request",
      deferredCredentialResponse.success,
      deferredCredentialResponse.durationMs ?? 0,
    );
    assertStepSuccess(
      deferredCredentialResponse,
      "Deferred Credential Request",
    );

    this.saveFirstCredentialIfConfigured(deferredCredentialResponse);

    return deferredCredentialResponse;
  }

  private resetResponses(): void {
    this._authorizeResponse = undefined;
    this._credentialResponse = undefined;
    this._deferredCredentialResponse = undefined;
    this._fetchMetadataResponse = undefined;
    this._nonceResponse = undefined;
    this._notificationRequestResponse = undefined;
    this._pushedAuthorizationRequestResponse = undefined;
    this._tokenResponse = undefined;
    this._walletAttestationResponse = undefined;
  }

  /**
   * Executes the Re-Issuance flow from metadata discovery through the
   * refresh-token token request. Does NOT run PAR or authorization steps.
   */
  private async runThroughRefreshToken(
    refreshToken: string,
  ): Promise<RunThroughRefreshTokenContext> {
    this.printTestSuiteOnce();
    this.log.info("Starting Re-Issuance Flow...");

    const { credentialConfigurationIds, credentialIssuer } =
      await this.findCredentialConfig();

    this.log.info(
      `Re-issuing credentials ${JSON.stringify(credentialConfigurationIds)} from issuer ${credentialIssuer}`,
    );

    const fetchMetadataResponse = await this.fetchMetadataStep.run({
      baseUrl: credentialIssuer,
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

    const walletAttestationResponse = await loadAttestation({
      trust: this.config.trust,
      trustAnchor: this.config.trust_anchor,
      wallet: this.config.wallet,
    });
    this._walletAttestationResponse = walletAttestationResponse;

    const callbacks = {
      ...partialCallbacks,
      signJwt: signJwtCallback([walletAttestationResponse.unitKey.privateKey]),
    };

    const entityStatementClaims =
      fetchMetadataResponse.response?.entityStatementClaims;
    if (!entityStatementClaims) {
      throw new OrchestratorError(
        "Fetch Metadata step returned no entity statement claims.",
        "ENTITY_STATEMENT_CLAIMS_MISSING",
      );
    }

    const popAttestation = await createClientAttestationPopJwt({
      authorizationServer: credentialIssuer,
      callbacks,
      clientAttestation: walletAttestationResponse.attestation,
      config: new IoWalletSdkConfig({
        itWalletSpecsVersion: this.config.wallet.wallet_version,
      }),
      jti: randomUUID(),
    });

    const tokenEndpoint =
      entityStatementClaims.metadata?.oauth_authorization_server
        ?.token_endpoint;
    if (!tokenEndpoint) {
      throw new IssuerMetadataError(
        "token_endpoint",
        "oauth_authorization_server",
        "Re-Issuance Token Request",
      );
    }

    // refresh_token is guaranteed non-null here — passed from reissuance()
    // after a null-check guard.
    const accessTokenRequest: AccessTokenRequest = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    };

    const tokenResponse = await this.tokenRequestStep.run({
      accessTokenEndpoint: tokenEndpoint,
      accessTokenRequest,
      popAttestation,
      walletAttestation: walletAttestationResponse,
    });
    this._tokenResponse = tokenResponse;
    this.log.flowStep(
      4,
      this.TOTAL_STEPS,
      "Re-Issuance Token Request",
      tokenResponse.success,
      tokenResponse.durationMs ?? 0,
    );
    assertStepSuccess(tokenResponse, "Re-Issuance Token Request");

    const dPoPKey = tokenResponse.response?.dPoPKey;
    if (!dPoPKey) throw new StepOutputError("TOKEN_REQUEST", "dPoPKey");

    return {
      credentialIssuer,
      dPoPKey,
      fetchMetadataResponse,
      tokenResponse,
      walletAttestationResponse,
    };
  }

  private saveFirstCredentialIfConfigured(
    deferredCredentialResponse: DeferredCredentialRequestResponse,
  ): void {
    if (!this.config.issuance.save_credential) return;

    const firstCredential =
      deferredCredentialResponse.response &&
      "credentials" in deferredCredentialResponse.response
        ? (
            deferredCredentialResponse.response as {
              credentials: { credential?: string }[];
            }
          ).credentials?.[0]
        : undefined;

    if (!firstCredential?.credential) return;

    const savedPath = saveCredentialToDisk(
      this.config.wallet.credentials_storage_path,
      this.issuanceConfig.credentialConfigurationId,
      firstCredential.credential,
      this.config.wallet.wallet_version,
    );
    if (savedPath) {
      this.log.info(`Deferred credential saved to disk: ${savedPath}`);
    } else {
      this.log.error("Failed to save deferred credential to disk");
    }
  }

  private async sendCredentialDeletedNotificationIfNeeded({
    accessToken,
    credentialResponse,
    dPoPKey,
    fetchMetadataResponse,
  }: {
    accessToken: string;
    credentialResponse: CredentialRequestResponse;
    dPoPKey: KeyPair;
    fetchMetadataResponse: FetchMetadataStepResponse;
  }): Promise<void> {
    if (this.config.issuance.save_credential) return;

    const notificationId = credentialResponse.response?.notification_id;
    if (!notificationId) return;

    this.log.info(
      "Credential Response contains 'notification_id' and 'save_credential' is false. Calling Notification Endpoint for credential_deleted event.",
    );

    const notificationEndpoint =
      this.getCredentialDeletedNotificationEndpoint(fetchMetadataResponse);
    if (!notificationEndpoint) {
      this.log.info(
        "Issuer metadata does not expose 'notification_endpoint'; skipping Notification Request step.",
      );
      return;
    }

    const notificationRequestResponse = await this.notificationRequestStep.run({
      accessToken,
      dPoPKey,
      event: "credential_deleted",
      notificationEndpoint,
      notificationId,
    });
    this._notificationRequestResponse = notificationRequestResponse;
    this.log.flowStep(
      this.ISSUANCE_WITH_DELETED_TOTAL_STEPS,
      this.ISSUANCE_WITH_DELETED_TOTAL_STEPS,
      "Notification Request",
      notificationRequestResponse.success,
      notificationRequestResponse.durationMs ?? 0,
    );
    assertStepSuccess(notificationRequestResponse, "Notification Request");
  }
}
