import {
  CallbackContext,
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  BaseCredentialRequestOptions,
  createCredentialRequest,
  CredentialRequest,
  CredentialRequestOptions,
  CredentialResponse,
  fetchCredentialResponse,
  FetchCredentialResponseOptions,
  ImmediateCredentialResponse,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import {
  buildJwksPath,
  createAndSaveKeys,
  createKeys,
  fetchWithConfig,
  loadWalletProviderCertificate,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { AttestationResponse } from "@/types/attestation-response";
import { KeyPair } from "@/types/key-pair";

import { StepFlow, StepResponse } from "../step-flow";

export type CredentialRequestExecuteResponse = ImmediateCredentialResponse & {
  credentialKeyPair: KeyPair;
};

export type CredentialRequestResponse = StepResponse & {
  response?: CredentialRequestExecuteResponse;
};

export interface CredentialRequestStepOptions {
  /**
   * Access Token fetched during the TokenRequestStep
   */
  accessToken: string;

  /**
   * Credential Issuer Base URL
   */
  baseUrl: string;

  /**
   * Client ID of the OAuth2 Client, it will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  /**
   * Optional overrides for the credential request options passed to createCredentialRequest.
   * When provided, these values are spread over the computed defaults, allowing tests to
   * manipulate the credential proof (e.g. swap the signJwt callback, change nonce, override signer).
   * `callbacks` is deep-merged so that omitted callbacks (e.g. `hash`) are always preserved.
   */
  createCredentialRequestOverrides?: Partial<BaseCredentialRequestOptions> & {
    callbacks?: Partial<Pick<CallbackContext, "hash" | "signJwt">>;
  };

  /**
   * Identifier of the credential to request, used to select the credential from the issuer metadata,
   */
  credentialIdentifier: string;

  /**
   * Credential Request Endpoint URL, it will be loaded from the issuer metadata
   */
  credentialRequestEndpoint: string;

  /**
   * Ephemeral DPoP key pair generated during the Token Request Step.
   * MUST be the same key used to create the DPoP proof at the Token Endpoint.
   */
  dPoPKey: KeyPair;

  /**
   * Optional pre-built DPoP JWT string.
   * When provided, this value is used as the DPoP proof instead of building one from the unit key.
   * Pass an invalid or empty string to simulate DPoP attack scenarios.
   */
  dPoPOverride?: string;

  /**
   * Nonce fetched during the NonceRequestStep
   */
  nonce: string;

  /**
   * Wallet Attestation used to authenticate the client, it will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

/**
 * Flow step to request a credential from the issuer's credential endpoint.
 * It uses the access token obtained in the Token Request Step and the nonce from the Nonce Request Step.
 */
export class CredentialRequestDefaultStep extends StepFlow {
  tag = "CREDENTIAL_REQUEST";

  async createKeyAttestation(
    walletAttestation: CredentialRequestStepOptions["walletAttestation"],
    credentialKeyPair: KeyPair,
  ): Promise<string> {
    const { providerKey } = walletAttestation;

    const x5c = await loadWalletProviderCertificate(
      this.config.wallet,
      providerKey,
    );

    const provider = new WalletProvider(this.ioWalletSdkConfig);

    return provider.createItKeyAttestationJwt({
      attestedKeys: [credentialKeyPair.publicKey],
      callbacks: {
        signJwt: signJwtCallback([providerKey.privateKey]),
      },
      issuer: this.config.wallet.wallet_provider_base_url,
      keyStorage: ["iso_18045_basic"],
      signer: {
        alg: "ES256",
        kid: providerKey.publicKey.kid,
        method: "x5c",
        x5c,
      },
      status: {
        status_list: {
          idx: 0,
          uri: `https://127.0.0.1:${this.config.trust_anchor.port}/wallet/status-list`,
        },
      },
      userAuthentication: ["iso_18045_basic"],
    });
  }

  async run(
    options: CredentialRequestStepOptions,
  ): Promise<CredentialRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.debug("Starting Credential Request Step");

    log.info("Generating new key pair for credential...");
    const credentialKeyPair = await this.generateCredentialKeyPair(
      options.credentialIdentifier,
    );

    return this.execute<CredentialRequestExecuteResponse>(async () => {
      log.info("Creating the Credential Request...");
      const credentialRequest = await this.buildCredentialRequest(
        options,
        credentialKeyPair,
      );

      log.info("Generating DPoP...");
      const dpop =
        options.dPoPOverride !== undefined
          ? options.dPoPOverride
          : await this.buildDPoP(options);

      log.info(
        `Fetching Credential Response from ${options.credentialRequestEndpoint}`,
      );
      log.debug(
        `Credential request credentialIdentifier: ${options.credentialIdentifier}`,
      );
      const credentialResponse = await this.fetchCredential(
        options,
        credentialRequest,
        dpop,
      );

      return {
        credentialKeyPair,
        ...credentialResponse,
      } as CredentialRequestExecuteResponse;
    });
  }

  private async buildCredentialRequest(
    options: CredentialRequestStepOptions,
    credentialKeyPair: KeyPair,
  ): Promise<CredentialRequest> {
    const baseOptions = {
      callbacks: {
        hash: partialCallbacks.hash,
        signJwt: signJwtCallback([credentialKeyPair.privateKey]),
      },
      clientId: options.clientId,
      credential_identifier: options.credentialIdentifier,
      issuerIdentifier: options.baseUrl,
      nonce: options.nonce,
    };

    const { callbacks: callbacksOverride, ...restOverrides } =
      options.createCredentialRequestOverrides ?? {};
    const commonOptions = {
      ...baseOptions,
      ...restOverrides,
      // Deep-merge callbacks so that partial overrides (e.g. only signJwt) never
      // lose required callbacks like `hash` that V1.3 mandates.
      callbacks: {
        ...baseOptions.callbacks,
        ...callbacksOverride,
      } satisfies typeof baseOptions.callbacks,
    };

    if (this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_3)) {
      const keyAttestation = await this.createKeyAttestation(
        options.walletAttestation,
        credentialKeyPair,
      );

      return createCredentialRequest({
        ...commonOptions,
        config: this.ioWalletSdkConfig,
        keyAttestation,
        signers: [
          {
            alg: "ES256",
            method: "jwk" as const,
            publicJwk: credentialKeyPair.publicKey,
          },
        ],
      } satisfies CredentialRequestOptions);
    }

    return createCredentialRequest({
      ...commonOptions,
      config: this
        .ioWalletSdkConfig as IoWalletSdkConfig<ItWalletSpecsVersion.V1_0>,
      signer: {
        alg: "ES256",
        method: "jwk" as const,
        publicJwk: credentialKeyPair.publicKey,
      },
    });
  }

  private async buildDPoP(
    options: CredentialRequestStepOptions,
  ): Promise<string> {
    const { dPoPKey } = options;

    const dpopOptions: CreateTokenDPoPOptions = {
      accessToken: options.accessToken,
      callbacks: {
        ...partialCallbacks,
        signJwt: signJwtCallback([dPoPKey.privateKey]),
      },
      signer: {
        alg: "ES256",
        method: "jwk",
        publicJwk: dPoPKey.publicKey,
      },
      tokenRequest: {
        method: "POST",
        url: options.credentialRequestEndpoint,
      },
    };

    const { jwt } = await createTokenDPoP(dpopOptions);

    return jwt;
  }

  private async fetchCredential(
    options: CredentialRequestStepOptions,
    credentialRequest: CredentialRequest,
    dpop: string,
  ): Promise<CredentialResponse> {
    const fetchOptions: FetchCredentialResponseOptions = {
      accessToken: options.accessToken,
      callbacks: { fetch: fetchWithConfig(this.config.network) },
      credentialEndpoint: options.credentialRequestEndpoint,
      credentialRequest,
      dPoP: dpop,
    };

    return fetchCredentialResponse(fetchOptions);
  }

  private async generateCredentialKeyPair(
    credentialIdentifier: string,
  ): Promise<KeyPair> {
    if (!this.config.issuance.save_credential) {
      return createKeys();
    }

    const jwksPath = buildJwksPath(
      `${this.config.wallet.backup_storage_path}/${credentialIdentifier}`,
    );

    return createAndSaveKeys(jwksPath);
  }
}
