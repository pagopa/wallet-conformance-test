import {
  createClientAttestationPopJwt,
  CreateClientAttestationPopJwtOptions,
  CreatePushedAuthorizationRequestOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  ItWalletEntityStatementClaims,
  itWalletEntityStatementClaimsSchema,
} from "@pagopa/io-wallet-oid-federation";

import { loadAttestation } from "@/functions";
import { signJwtCallback } from "@/logic/jwt";
import { createLogger } from "@/logic/logs";
import { loadConfig } from "@/logic/utils";
import { partialCallbacks } from "@/logic/utils";
import {
  FetchMetadataOptions,
  FetchMetadataStep,
  FetchMetadataStepResponse,
} from "@/step/issuance/fetch-metadata-step";
import {
  PushedAuthorizationRequestOptions,
  PushedAuthorizationRequestResponse,
  PushedAuthorizationRequestStep,
  PushedAuthorizationRequestStepOptions,
} from "@/step/issuance/pushed-authorization-request-step";
import { Config } from "@/types";

export interface WalletIssuanceOrchestratorFlowRunOptions {
  credentialConfiguration: {
    id: string;
    scope: string;
  };
  fetchMetadataOptions?: FetchMetadataOptions;
  pushedAuthorizationRequestOptions?: PushedAuthorizationRequestOptions;
  testName: string;
}

export class WalletIssuanceOrchestratorFlow {
  private config: Config;
  private fetchMetadataStep: FetchMetadataStep;
  private log = createLogger();

  private pushedAuthorizationRequestStep: PushedAuthorizationRequestStep;
  private testName: string;

  constructor(testName: string) {
    this.testName = testName;
    this.log = this.log.withTag(this.testName);

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

    this.fetchMetadataStep = new FetchMetadataStep(this.config, this.log);
    this.pushedAuthorizationRequestStep = new PushedAuthorizationRequestStep(
      this.config,
      this.log,
    );
  }

  async fetchMetadata(
    options: FetchMetadataOptions,
  ): Promise<FetchMetadataStepResponse> {
    const result = await this.fetchMetadataStep.run(options);
    if (!result.success) throw result.error;
    return result;
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async pushedAuthorizationRequest(
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    const result = await this.pushedAuthorizationRequestStep.run(options);
    if (!result.success) throw result.error;
    return result;
  }

  async runAll(options: WalletIssuanceOrchestratorFlowRunOptions): Promise<{
    fetchMetadataResponse: FetchMetadataStepResponse;
    //pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
  }> {
    try {
      this.log.info("Starting Test Issuance Flow...");

      const { fetchMetadataOptions, pushedAuthorizationRequestOptions } =
        options;
      this.log.debug(
        "Fetch Metadata Options: ",
        JSON.stringify(fetchMetadataOptions),
      );
      const fetchMetadataResponse = await this.fetchMetadata({
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
      //     credential_configuration_id: options.credentialConfiguration.id,
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

      // const pushedAuthorizationRequestResponse = await this.pushedAuthorizationRequest({
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
