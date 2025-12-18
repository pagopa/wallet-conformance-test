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
import { Config } from "@/types";

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

    this.authorizationRequestStep = new AuthorizationRequestDefaultStep(
      this.config,
      this.log,
    );

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

      const fetchMetadataOptions =
        this.presentationConfig.fetchMetadata?.options;

      this.log.debug(
        "Fetch Metadata Options: ",
        JSON.stringify(fetchMetadataOptions),
      );

      const fetchMetadataResponse = await this.fetchMetadataStep.run({
        baseUrl:
          fetchMetadataOptions?.baseUrl || this.config.presentation.verifier,
        entityStatementClaimsSchema:
          fetchMetadataOptions?.entityStatementClaimsSchema ||
          itWalletEntityStatementClaimsSchema,
        wellKnownPath:
          fetchMetadataOptions?.wellKnownPath ||
          "/.well-known/openid-federation",
      });

      const trustAnchorBaseUrl = `https://127.0.0.1:${this.config.server.port}`;

      this.log.info("Loading Wallet Attestation...");
      const walletAttestation = await loadAttestation({
        trustAnchorBaseUrl,
        trustAnchorJwksPath:
          this.config.trust.federation_trust_anchors_jwks_path,
        wallet: this.config.wallet,
      });

      this.log.info("Wallet Attestation Loaded.");
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

      const authorizationRequestResponse =
        await this.authorizationRequestStep.run({
          authorizeRequestUrl: this.config.presentation.authorize_request_url,
          credentials: [pid.compact],
          rpMetadata,
          walletAttestation,
        });

      if (!authorizationRequestResponse.response) {
        throw new Error("Authorization Request Step did not return a response");
      }

      const redirectUriResponse = await this.redirectUriStep.run({
        authorizationResponse:
          authorizationRequestResponse.response.authorizationResponse,
        responseUri: authorizationRequestResponse.response.responseUri,
      });

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
}
