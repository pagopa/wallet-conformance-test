import { IssuerTestConfiguration } from "#/config";
import {
  AccessTokenRequest,
  createClientAttestationPopJwt,
} from "@pagopa/io-wallet-oauth2";
import { resolveCredentialOffer } from "@pagopa/io-wallet-oid4vci";

import { loadAttestation, loadCredentialsForPresentation } from "@/functions";
import {
  createLogger,
  loadConfigWithHierarchy,
  partialCallbacks,
  saveCredentialToDisk,
  signJwtCallback,
} from "@/logic";
import { REDIRECT_URI } from "@/logic/constants";
import {
  CredentialConfigurationError,
  IssuerMetadataError,
  OrchestratorError,
  StepOutputError,
} from "@/orchestrator/errors";
import {
  AuthorizeDefaultStep,
  AuthorizeStepResponse,
  CredentialRequestDefaultStep,
  CredentialRequestResponse,
  FetchMetadataDefaultStep,
  FetchMetadataStepResponse,
  NonceRequestDefaultStep,
  NonceRequestResponse,
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestResponse,
  TokenRequestDefaultStep,
  TokenRequestResponse,
} from "@/step/issuance";
import { assertStepSuccess } from "@/step/step-flow";
import {
  AttestationResponse,
  Config,
  IssuanceFlowResponse,
  RunThroughAuthorizeContext,
  RunThroughParContext,
  RunThroughTokenContext,
} from "@/types";

export class WalletIssuanceOrchestratorFlow {
  private _authorizeResponse?: AuthorizeStepResponse;
  private _credentialResponse?: CredentialRequestResponse;
  private _fetchMetadataResponse?: FetchMetadataStepResponse;
  private _nonceResponse?: NonceRequestResponse;
  private _pushedAuthorizationRequestResponse?: PushedAuthorizationRequestResponse;
  private _suitePrinted = false;
  private _tokenResponse?: TokenRequestResponse;

  private _walletAttestationResponse?: AttestationResponse;

  private authorizeStep: AuthorizeDefaultStep;
  private config: Config;
  private credentialRequestStep: CredentialRequestDefaultStep;
  private fetchMetadataStep: FetchMetadataDefaultStep;
  private issuanceConfig: IssuerTestConfiguration;
  private log = createLogger();

  private nonceRequestStep: NonceRequestDefaultStep;
  private pushedAuthorizationRequestStep: PushedAuthorizationRequestDefaultStep;
  private tokenRequestStep: TokenRequestDefaultStep;
  private readonly TOTAL_STEPS = 6;

  constructor(issuanceConfig: IssuerTestConfiguration) {
    this.issuanceConfig = issuanceConfig;
    this.log = this.log.withTag(this.issuanceConfig.name);

    this.config = loadConfigWithHierarchy();

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
      if (!accessToken) throw new StepOutputError("TOKEN", "access_token");

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
      if (!nonce) throw new StepOutputError("NONCE", "c_nonce");

      const credentialResponse = await this.credentialRequestStep.run({
        accessToken,
        baseUrl: credentialIssuer,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialIdentifier: this.issuanceConfig.credentialConfigurationId,
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

      return {
        authorizeResponse,
        credentialResponse,
        fetchMetadataResponse,
        nonceResponse,
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
        pushedAuthorizationRequestResponse:
          this._pushedAuthorizationRequestResponse,
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
      network: this.config.network,
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
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
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

    const { requestObject } = authorizeResponse.response;
    if (!requestObject)
      throw new StepOutputError("AUTHORIZE", "request_object");

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
      redirect_uri: REDIRECT_URI,
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

  private resetResponses(): void {
    this._authorizeResponse = undefined;
    this._credentialResponse = undefined;
    this._fetchMetadataResponse = undefined;
    this._nonceResponse = undefined;
    this._pushedAuthorizationRequestResponse = undefined;
    this._tokenResponse = undefined;
    this._walletAttestationResponse = undefined;
  }
}
