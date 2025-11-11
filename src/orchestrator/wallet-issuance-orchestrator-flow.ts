import {
  createClientAttestationPopJwt,
  CreateClientAttestationPopJwtOptions,
  CreatePushedAuthorizationRequestOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  ItWalletEntityStatementClaims,
  itWalletEntityStatementClaimsSchema,
} from "@pagopa/io-wallet-oid-federation";
import { IssuerTestConfiguration } from "tests/config/issuance-test-configuration";

import { loadAttestation } from "@/functions";
import { signJwtCallback } from "@/logic/jwt";
import { createLogger } from "@/logic/logs";
import { loadConfig } from "@/logic/utils";
import { partialCallbacks } from "@/logic/utils";
import {
  FetchMetadataOptions,
  FetchMetadataDefaultStep,
  FetchMetadataStepResponse,
} from "@/step/issuance/fetch-metadata-step";
import {
  PushedAuthorizationRequestOptions,
  PushedAuthorizationRequestResponse,
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestStepOptions,
} from "@/step/issuance/pushed-authorization-request-step";
import { Config } from "@/types";

export class WalletIssuanceOrchestratorFlow {
  private config: Config;
  private fetchMetadataStep: FetchMetadataDefaultStep;
  private issuanceConfig: IssuerTestConfiguration;

  private log = createLogger();
  private pushedAuthorizationRequestStep: PushedAuthorizationRequestDefaultStep;

  constructor(issuanceConfig: IssuerTestConfiguration) {
    this.issuanceConfig = issuanceConfig;
    this.log = this.log.withTag(this.issuanceConfig.testName);

    this.config = loadConfig("./config.ini");

    this.log.setLogOptions({
      format: this.config.logging.log_format,
      level: this.config.logging.log_level,
      path: this.config.logging.log_file,
    });

    this.log.info("Setting Up Wallet conformance Tests - Issuance Flow");
    this.log.info("Configuration Loaded from config.ini");

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
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async issuance(): Promise<{
    fetchMetadataResponse: FetchMetadataStepResponse;
    //pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
  }> {
    try {
      this.log.info("Starting Test Issuance Flow...");

      const fetchMetadataOptions = this.issuanceConfig.fetchMetadata?.options;

      this.log.debug(
        "Fetch Metadata Options: ",
        JSON.stringify(fetchMetadataOptions),
      );
      const fetchMetadataResponse = await this.fetchMetadataStep.run({
        entityStatementClaimsSchema:
          fetchMetadataOptions?.entityStatementClaimsSchema ||
          itWalletEntityStatementClaimsSchema,
        wellKnownPath:
          fetchMetadataOptions?.wellKnownPath ||
          `/.well-known/openid-federation`,
      });

      this.log.info("Loading Wallet Attestation...");
      const walletAttestationResponse = await loadAttestation(
        this.config.wallet,
      );

      // this.log.info("Creating Client Attestation DPoP...");
      // const callbacks = {
      //   ...partialCallbacks,
      //   signJwt: signJwtCallback([walletAttestationResponse.unitKey.privateKey]),
      // };

      // const itWalletEntityStatementClaims : ItWalletEntityStatementClaims = fetchMetadataResponse.response?.entityStatementClaims;

      // const clientAttestationDPoP = await createClientAttestationPopJwt({
      //   clientAttestation: walletAttestationResponse.attestation,
      //   authorizationServer: itWalletEntityStatementClaims.iss,
      //   callbacks,
      // });

      // this.log.info("Sending Pushed Authorization Request...");

      // const createParOptions: CreatePushedAuthorizationRequestOptions = {
      //   audience: this.config.issuance.url,
      //   authorization_details: [{
      //     type: "openid_credential",
      //     credential_configuration_id: options.credentialConfigurationId,
      //   }],
      //   callbacks: callbacks as CreatePushedAuthorizationRequestOptions["callbacks"],
      //   codeChallengeMethodsSupported: ["S256"],
      //   redirectUri: "https://client.example.org/cb",
      //   responseMode: "query",
      //   clientId: walletAttestationResponse.unitKey.publicKey.kid!,
      //   dpop: {
      //     signer: {
      //       publicJwk: {
      //         ...walletAttestationResponse.unitKey.publicKey,
      //         kid: walletAttestationResponse.unitKey.publicKey.kid!,
      //       },
      //       method: "jwk",
      //       alg: "ES256",
      //     },
      //   },
      //   scope: options.credentialConfiguration.scope,
      // };

      // const pushedAuthorizationRequestResponse = await this.pushedAuthorizationRequestStep.run({
      //   ...createParOptions,
      //   attestation: pushedAuthorizationRequestOptions?.attestation || walletAttestationResponse.attestation,
      //   attestationPoP: pushedAuthorizationRequestOptions?.attestationPoP || clientAttestationDPoP,
      //   clientId: pushedAuthorizationRequestOptions?.clientId || walletAttestationResponse.unitKey.publicKey.kid!,
      //   pushedAuthorizationRequestEndpoint: pushedAuthorizationRequestOptions?.pushedAuthorizationRequestEndpoint || itWalletEntityStatementClaims.metadata!.oauth_authorization_server!.pushed_authorization_request_endpoint!
      // });

      return {
        fetchMetadataResponse,
        //pushedAuthorizationRequestResponse,
      };
    } catch (e) {
      this.log.error("Error in Issuer Flow Tests!", e);
      throw e;
    }
  }
}
