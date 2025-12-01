import { PresentationTestConfiguration } from "#/config";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";

import { createLogger, loadConfig } from "@/logic";
import {
  FetchMetadataDefaultStep,
  FetchMetadataStepResponse,
} from "@/step/fetch-metadata-step";
import {
  AuthorizationRequestStep,
  AuthorizationRequestStepResponse,
} from "@/step/presentation/authorization-request-step";
import { Config } from "@/types";

export class WalletPresentationOrchestratorFlow {
  private authorizationRequestStep: AuthorizationRequestStep;
  private config: Config;
  private fetchMetadataStep: FetchMetadataDefaultStep;

  private log = createLogger();
  private presentationConfig: PresentationTestConfiguration;

  constructor(presentationConfig: PresentationTestConfiguration) {
    this.presentationConfig = presentationConfig;
    this.log = this.log.withTag(this.presentationConfig.name);

    this.config = loadConfig("./config.ini");

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

    this.authorizationRequestStep = new AuthorizationRequestStep(
      this.config,
      this.log,
    );
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async presentation(): Promise<{
    authorizationRequestResponse: AuthorizationRequestStepResponse;
    fetchMetadataResponse: FetchMetadataStepResponse;
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
        baseUrl: this.config.presentation.verifier,
        entityStatementClaimsSchema:
          fetchMetadataOptions?.entityStatementClaimsSchema ||
          itWalletEntityStatementClaimsSchema,
        wellKnownPath:
          fetchMetadataOptions?.wellKnownPath ||
          "/.well-known/openid-federation",
      });

      const entityStatementClaims =
        fetchMetadataResponse.response?.entityStatementClaims;
      if (!entityStatementClaims) {
        throw new Error("Entity Statement Claims not found in response");
      }

      const verifierMetadata =
        entityStatementClaims.metadata.openid_credential_verifier;
      if (!verifierMetadata) {
        throw new Error(
          "Verifier metadata (openid_credential_verifier) not found",
        );
      }

      const authorizationRequestResponse =
        await this.authorizationRequestStep.run({
          authorizeRequestUrl: this.config.presentation.authorize_request_url,
        });

      return { authorizationRequestResponse, fetchMetadataResponse };
    } catch (e) {
      this.log.error("Error in Presentation Flow Tests!", e);
      throw e;
    }
  }
}
