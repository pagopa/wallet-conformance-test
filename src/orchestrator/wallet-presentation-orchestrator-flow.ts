import { PresentationTestConfiguration } from "#/config";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";

import { createMockSdJwt, loadAttestation, loadCredentials } from "@/functions";
import { createLogger, loadConfigWithHierarchy } from "@/logic";
import {
  FetchMetadataDefaultStep,
  FetchMetadataStepResponse,
} from "@/step/fetch-metadata-step";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestStepResponse,
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

    this.redirectUriStep = new RedirectUriDefaultStep(this.config, this.log);
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async presentation(): Promise<{
    authorizationRequestResponse: AuthorizationRequestStepResponse;
    fetchMetadataResponse: FetchMetadataStepResponse;
    redirectUriResponse: RedirectUriStepResponse;
  }> {
    try {
      this.log.info("Starting Test Presentation Flow...");

      const fetchMetadataResponse = await this.fetchVerifierMetadata();
      const rpMetadata = this.extractVerifierMetadata(fetchMetadataResponse);

      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.server.port}`;
      const walletAttestation =
        await this.loadWalletAttestation(trustAnchorBaseUrl);

      const pid = await this.prepareCredential(trustAnchorBaseUrl);

      const authorizationRequestResponse =
        await this.executeAuthorizationRequest(
          pid.compact,
          rpMetadata,
          walletAttestation,
        );

      const redirectUriResponse = await this.executeRedirectUri(
        authorizationRequestResponse,
      );

      return {
        authorizationRequestResponse,
        fetchMetadataResponse,
        redirectUriResponse,
      };
    } catch (e) {
      this.log.error("Error in Presentation Flow Tests!", e);
      throw e;
    }
  }

  private async executeAuthorizationRequest(
    credential: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    rpMetadata: any, // TODO: improve any type
    walletAttestation: AttestationResponse,
  ) {
    const authorizationOptions = this.presentationConfig.authorize?.options;

    const authorizationRequestResponse =
      await this.authorizationRequestStep.run({
        authorizeRequestUrl:
          authorizationOptions?.authorizeRequestUrl ||
          this.config.presentation.authorize_request_url,
        credentials: [credential],
        rpMetadata: authorizationOptions?.rpMetadata || rpMetadata,
        walletAttestation:
          authorizationOptions?.walletAttestation || walletAttestation,
      });

    if (!authorizationRequestResponse.response) {
      throw new Error("Authorization Request Step did not return a response");
    }

    return authorizationRequestResponse;
  }

  private async executeRedirectUri(
    authorizationRequestResponse: AuthorizationRequestStepResponse,
  ) {
    if (!authorizationRequestResponse.response) {
      throw new Error("Authorization Request response is missing");
    }

    return await this.redirectUriStep.run({
      authorizationResponse:
        authorizationRequestResponse.response.authorizationResponse,
      responseUri: authorizationRequestResponse.response.responseUri,
    });
  }

  private extractVerifierMetadata(
    fetchMetadataResponse: FetchMetadataStepResponse,
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

  private async fetchVerifierMetadata(): Promise<FetchMetadataStepResponse> {
    const fetchMetadataOptions = this.presentationConfig.fetchMetadata?.options;

    this.log.debug(
      "Fetch Metadata Options: ",
      JSON.stringify(fetchMetadataOptions),
    );

    return await this.fetchMetadataStep.run({
      baseUrl:
        fetchMetadataOptions?.baseUrl || this.config.presentation.verifier,
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

  private async prepareCredential(trustAnchorBaseUrl: string) {
    const credentials = await loadCredentials(
      this.config.wallet.credentials_storage_path,
      ["dc_sd_jwt_PersonIdentificationData"],
      this.log.error,
    );

    const pid = credentials.dc_sd_jwt_PersonIdentificationData
      ? credentials.dc_sd_jwt_PersonIdentificationData
      : await createMockSdJwt(
          {
            iss: this.config.issuance.url,
            trustAnchorBaseUrl,
            trustAnchorJwksPath:
              this.config.trust.federation_trust_anchors_jwks_path,
          },
          this.config.wallet.backup_storage_path,
          this.config.wallet.credentials_storage_path,
        );

    return pid;
  }
}
