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
import { randomUUID } from "node:crypto";

import {
  buildJwksPath,
  createAndSaveKeys,
  createKeys,
  fetchWithConfig,
  loadWalletProviderCertificate,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { getLocalWpBaseUrl } from "@/servers/wp-server";
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
   * Credential Issuer Base URL
   */
  credentialIssuer: string;

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
 * The parameter type of `WalletProvider.createItKeyAttestationJwt`, derived
 * directly from the SDK so it never drifts from the installed version.
 */
export type KeyAttestationOptions = Parameters<
  WalletProvider["createItKeyAttestationJwt"]
>[0];

/**
 * Flow step to request a credential from the issuer's credential endpoint.
 * It uses the access token obtained in the Token Request Step and the nonce from the Nonce Request Step.
 */
export class CredentialRequestDefaultStep extends StepFlow {
  static readonly tag = "CREDENTIAL_REQUEST";

  /**
   * Optional overrides merged into the key attestation options before signing.
   * Intended for conformance tests that need to submit non-standard security
   * claim values (e.g. unsupported keyStorage / userAuthentication levels) to
   * verify that the Credential Issuer enforces its security requirements.
   *
   * When set, fields in this object replace the corresponding defaults computed
   * inside `createKeyAttestation`. The SDK does not perform runtime Zod
   * validation on these fields, so intentionally non-compliant string values
   * will reach the issuer inside the signed JWT.
   */
  protected keyAttestationOverrides?: Partial<KeyAttestationOptions>;

  async createKeyAttestation(
    walletAttestation: CredentialRequestStepOptions["walletAttestation"],
    credentialKeyPair: KeyPair,
  ): Promise<string> {
    const { providerKey } = walletAttestation;

    const x5c = await loadWalletProviderCertificate(
      this.config.wallet,
      this.config.trust,
      providerKey,
    );

    const provider = new WalletProvider(this.ioWalletSdkConfig);

    const defaults: KeyAttestationOptions = {
      attestedKeys: [credentialKeyPair.publicKey],
      callbacks: {
        signJwt: signJwtCallback([providerKey.privateKey]),
      },
      issuer: getLocalWpBaseUrl(this.config.wallet.port),
      keyStorage: ["iso_18045_moderate"],
      signer: {
        alg: "ES256",
        kid: providerKey.publicKey.kid,
        method: "x5c",
        x5c,
      },
      status: {
        status_list: {
          idx: 4373,
          uri: `https://iwuitncdnst01.blob.core.windows.net/status-lists/ae783554-e4cd-4646-a73e-337a0062c60d`,
        },
      },
      userAuthentication: ["iso_18045_moderate"],
    };

    return provider.createItKeyAttestationJwt({
      ...defaults,
      ...this.keyAttestationOverrides,
    } as KeyAttestationOptions);
  }

  async run(
    options: CredentialRequestStepOptions,
  ): Promise<CredentialRequestResponse> {
    const log = this.log;

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
      log.debug(
        "Credential Request:",
        JSON.stringify(credentialRequest, null, 2),
      );

      log.info("Generating DPoP...");
      const dpop =
        options.dPoPOverride !== undefined
          ? options.dPoPOverride
          : await this.buildDPoP(options);
      log.debug("DPoP JWT:", dpop);

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
      log.debug(
        "Credential Response:",
        JSON.stringify(credentialResponse, null, 2),
      );

      return {
        credentialKeyPair,
        ...credentialResponse,
      } as CredentialRequestExecuteResponse;
    });
  }

  tag(): string {
    return CredentialRequestDefaultStep.tag;
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
      issuerIdentifier: options.credentialIssuer,
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

      this.log.debug("Key Attestation JWT created:", keyAttestation);

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
      jti: randomUUID(),
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
