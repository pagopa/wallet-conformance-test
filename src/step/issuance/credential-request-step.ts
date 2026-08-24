import {
  CallbackContext,
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  BaseCredentialRequestOptions,
  createCredentialRequest,
  CredentialRequest,
  CredentialRequestOptionsV1_3,
  CredentialRequestOptionsV1_4,
  CredentialResponse,
  fetchCredentialResponse,
  FetchCredentialResponseOptions,
  ImmediateCredentialResponse,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { randomUUID } from "node:crypto";

import {
  assertNever,
  buildJwksPath,
  createAndSaveKeys,
  createKeys,
  fetchWithConfig,
  loadWalletProviderCertificate,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { resolveWalletProviderBaseUrl } from "@/logic/wallet-provider-url";
import { AttestationResponse } from "@/types/attestation-response";
import { KeyPair } from "@/types/key-pair";

import { StepFlow, StepResponse } from "../step-flow";

export type CredentialRequestExecuteResponse = CredentialResponse & {
  credentialKeyPairs: KeyPair[];
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
   * Number of credentials to request for this single credential identifier.
   * Applies only to IT-Wallet v1.3/v1.4 batch credential issuance; v1.0 always
   * remains a single-proof request.
   */
  batchSize?: number;

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

export type DeferredCredentialRequestExecuteResponse =
  CredentialRequestExecuteResponse &
    Extract<CredentialResponse, { transaction_id: string }>;

export type ImmediateCredentialRequestExecuteResponse =
  CredentialRequestExecuteResponse & ImmediateCredentialResponse;

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
    credentialKeyPairs: KeyPair[],
  ): Promise<string> {
    const { providerKey } = walletAttestation;
    const [firstCredentialKeyPair, ...otherCredentialKeyPairs] =
      credentialKeyPairs;
    if (!firstCredentialKeyPair) {
      throw new Error("At least one credential key pair is required");
    }

    const x5c = await loadWalletProviderCertificate(
      this.config.wallet,
      this.config.trust,
      providerKey,
    );

    const provider = new WalletProvider(this.ioWalletSdkConfig);

    const defaults: KeyAttestationOptions = {
      attestedKeys: [
        firstCredentialKeyPair.publicKey,
        ...otherCredentialKeyPairs.map(
          (credentialKeyPair) => credentialKeyPair.publicKey,
        ),
      ],
      callbacks: {
        signJwt: signJwtCallback([providerKey.privateKey]),
      },
      expiresAt: new Date(Date.now() + 3600 * 1000), // 1 hour expiration
      issuer: resolveWalletProviderBaseUrl(this.config.wallet),
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

    const batchSize = this.getCredentialBatchSize(options);

    log.info(`Generating ${batchSize} new key pair(s) for credential...`);
    const credentialKeyPairs = await this.generateCredentialKeyPairs(
      options.credentialIdentifier,
      batchSize,
    );

    return this.execute<CredentialRequestExecuteResponse>(async () => {
      log.info("Creating the Credential Request...");
      const credentialRequest = await this.buildCredentialRequest(
        options,
        credentialKeyPairs,
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
      log.debug(`Credential request batchSize: ${batchSize}`);
      const credentialResponse = await this.fetchCredential(
        options,
        credentialRequest,
        dpop,
      );
      if (
        "credentials" in credentialResponse &&
        credentialResponse.credentials.length !== credentialKeyPairs.length
      ) {
        throw new Error(
          `credential response contains ${credentialResponse.credentials.length} credential(s), expected ${credentialKeyPairs.length}`,
        );
      }
      log.debug(
        "Credential Response:",
        JSON.stringify(credentialResponse, null, 2),
      );

      return {
        credentialKeyPairs,
        ...credentialResponse,
      } as CredentialRequestExecuteResponse;
    });
  }

  tag(): string {
    return CredentialRequestDefaultStep.tag;
  }

  private buildCredentialKeyPairIdentifier(
    credentialIdentifier: string,
    batchSize: number,
    index: number,
  ): string {
    return batchSize === 1
      ? credentialIdentifier
      : `${credentialIdentifier}-${index}`;
  }

  private async buildCredentialRequest(
    options: CredentialRequestStepOptions,
    credentialKeyPairs: KeyPair[],
  ): Promise<CredentialRequest> {
    const [credentialKeyPair] = credentialKeyPairs;
    if (!credentialKeyPair) {
      throw new Error("At least one credential key pair is required");
    }

    const baseOptions = {
      callbacks: {
        hash: partialCallbacks.hash,
        signJwt: signJwtCallback(
          credentialKeyPairs.map(
            (credentialKeyPair) => credentialKeyPair.privateKey,
          ),
        ),
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

    if (this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0)) {
      return createCredentialRequest({
        ...commonOptions,
        config: this.ioWalletSdkConfig,
        signer: {
          alg: "ES256",
          method: "jwk" as const,
          publicJwk: credentialKeyPair.publicKey,
        },
      });
    }

    if (this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_3)) {
      return createCredentialRequest({
        ...(await this.buildKeyAttestationOptions(
          options,
          credentialKeyPairs,
          commonOptions,
        )),
        config: this.ioWalletSdkConfig,
      } satisfies CredentialRequestOptionsV1_3);
    }

    if (this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_4)) {
      return createCredentialRequest({
        ...(await this.buildKeyAttestationOptions(
          options,
          credentialKeyPairs,
          commonOptions,
        )),
        config: this.ioWalletSdkConfig,
      } satisfies CredentialRequestOptionsV1_4);
    }

    // isVersion()'s `this is IoWalletSdkConfig<W>` predicate narrows the SDK
    // config generic above but can't prove the negative case, so this branch
    // still sees the full ItWalletSpecsVersion union. Switching over the known
    // members here makes the `default` provably unreachable (`never`) today —
    // adding a new spec version without a matching isVersion() branch above
    // breaks that exhaustiveness and fails the build instead of failing at runtime.
    switch (this.ioWalletSdkConfig.itWalletSpecsVersion) {
      case ItWalletSpecsVersion.V1_0:
      case ItWalletSpecsVersion.V1_3:
      case ItWalletSpecsVersion.V1_4:
        throw new Error(
          `unimplemented wallet_version for credential request: ${this.ioWalletSdkConfig.itWalletSpecsVersion}`,
        );
      default:
        return assertNever(this.ioWalletSdkConfig.itWalletSpecsVersion);
    }
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

  private async buildKeyAttestationOptions<
    T extends BaseCredentialRequestOptions,
  >(
    options: CredentialRequestStepOptions,
    credentialKeyPairs: KeyPair[],
    commonOptions: T,
  ) {
    const keyAttestation = await this.createKeyAttestation(
      options.walletAttestation,
      credentialKeyPairs,
    );

    this.log.debug("Key Attestation JWT created:", keyAttestation);

    return {
      ...commonOptions,
      keyAttestation,
      maxBatchSize: this.getCredentialBatchSize(options),
      signers: credentialKeyPairs.map((credentialKeyPair) => ({
        alg: "ES256" as const,
        method: "jwk" as const,
        publicJwk: credentialKeyPair.publicKey,
      })),
    };
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
    if (!this.config.issuance.save_credential) return createKeys();

    const jwksPath = buildJwksPath(
      `${this.config.wallet.backup_storage_path}/${credentialIdentifier}`,
    );

    return createAndSaveKeys(jwksPath);
  }

  private async generateCredentialKeyPairs(
    credentialIdentifier: string,
    batchSize: number,
  ): Promise<KeyPair[]> {
    return Promise.all(
      Array.from({ length: batchSize }, (_, index) =>
        this.generateCredentialKeyPair(
          this.buildCredentialKeyPairIdentifier(
            credentialIdentifier,
            batchSize,
            index,
          ),
        ),
      ),
    );
  }

  private getCredentialBatchSize(
    options: CredentialRequestStepOptions,
  ): number {
    if (this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_0)) return 1;

    const batchSize = options.batchSize ?? 1;
    if (!Number.isInteger(batchSize) || batchSize <= 0) {
      throw new Error(
        "credential request batchSize must be a positive integer",
      );
    }

    return batchSize;
  }
}

export function getCredentialResponseCredentials(
  response: CredentialRequestExecuteResponse | undefined,
): ImmediateCredentialResponse["credentials"] {
  return isImmediateCredentialRequestResponse(response)
    ? response.credentials
    : [];
}

export function getCredentialResponseNotificationId(
  response: CredentialRequestExecuteResponse | undefined,
): string | undefined {
  return isImmediateCredentialRequestResponse(response)
    ? response.notification_id
    : undefined;
}

export function getCredentialResponseTransactionId(
  response: CredentialRequestExecuteResponse | undefined,
): string | undefined {
  return isDeferredCredentialRequestResponse(response)
    ? response.transaction_id
    : undefined;
}

export function isDeferredCredentialRequestResponse(
  response: CredentialRequestExecuteResponse | undefined,
): response is DeferredCredentialRequestExecuteResponse {
  return response !== undefined && "transaction_id" in response;
}

export function isImmediateCredentialRequestResponse(
  response: CredentialRequestExecuteResponse | undefined,
): response is ImmediateCredentialRequestExecuteResponse {
  return response !== undefined && "credentials" in response;
}
