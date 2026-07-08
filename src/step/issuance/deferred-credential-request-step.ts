import {
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  CredentialResponse,
  zCredentialResponseV1_0,
  zCredentialResponseV1_3,
} from "@pagopa/io-wallet-oid4vci";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";

import { fetchWithConfig, partialCallbacks, signJwtCallback } from "@/logic";
import { KeyPair } from "@/types/key-pair";

import { StepFlow, StepResponse } from "../step-flow";

export type DeferredCredentialRequestResponse = StepResponse & {
  response?: CredentialResponse;
};

export interface DeferredCredentialRequestStepOptions {
  /**
   * DPoP-bound access token obtained from the token endpoint.
   */
  accessToken: string;

  /**
   * Deferred Credential Endpoint URL from the issuer metadata.
   */
  deferredCredentialEndpoint: string;

  /**
   * The same ephemeral DPoP key pair that was used to bind the access token.
   * MUST be reused here to produce a valid DPoP proof for the deferred request.
   */
  dPoPKey: KeyPair;

  /**
   * Transaction ID returned in the original (pending) credential response.
   */
  transactionId: string;
}

/**
 * Flow step to request a previously-pending credential from the issuer's
 * Deferred Credential Endpoint using a transaction_id and a valid access token.
 *
 * The step mirrors the credential-request pattern: it builds a DPoP proof with
 * the same ephemeral key pair used in the token request, then POSTs to the
 * deferred endpoint with the access token and the transaction_id in the body.
 */
export class DeferredCredentialRequestDefaultStep extends StepFlow {
  static readonly tag = "DEFERRED_CREDENTIAL_REQUEST";

  async run(
    options: DeferredCredentialRequestStepOptions,
  ): Promise<DeferredCredentialRequestResponse> {
    const log = this.log;

    log.debug("Starting Deferred Credential Request Step");

    return this.execute<CredentialResponse>(async () => {
      log.info("Generating DPoP for Deferred Credential Request...");
      const dpop = await this.buildDPoP(options);
      log.debug("DPoP JWT:", dpop);

      log.info(
        `Sending Deferred Credential Request to ${options.deferredCredentialEndpoint}`,
      );
      const response = await this.fetchDeferred(options, dpop);
      log.debug(
        "Deferred Credential Response:",
        JSON.stringify(response, null, 2),
      );

      return response;
    });
  }

  tag(): string {
    return DeferredCredentialRequestDefaultStep.tag;
  }

  private async buildDPoP(
    options: DeferredCredentialRequestStepOptions,
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
        url: options.deferredCredentialEndpoint,
      },
    };

    const { jwt } = await createTokenDPoP(dpopOptions);

    return jwt;
  }

  private async fetchDeferred(
    options: DeferredCredentialRequestStepOptions,
    dpop: string,
  ): Promise<CredentialResponse> {
    const customFetch = fetchWithConfig(this.config.network);

    const httpResponse = await customFetch(options.deferredCredentialEndpoint, {
      body: JSON.stringify({ transaction_id: options.transactionId }),
      headers: {
        Authorization: `DPoP ${options.accessToken}`,
        "Content-Type": "application/json",
        DPoP: dpop,
      },
      method: "POST",
    });

    if (!httpResponse.ok && httpResponse.status !== 202) {
      throw new Error(
        `Deferred Credential Request failed with status ${httpResponse.status}`,
      );
    }

    const body: unknown = await httpResponse.json();

    const schema =
      this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_3) ||
      this.ioWalletSdkConfig.isVersion(ItWalletSpecsVersion.V1_4)
        ? zCredentialResponseV1_3
        : zCredentialResponseV1_0;

    const parsedResponse = schema.parse(body);

    // Spec: on 202 (still pending), response transaction_id MUST equal the sent one
    if (httpResponse.status === 202 && "transaction_id" in parsedResponse) {
      const pending = parsedResponse as { transaction_id: string };
      if (pending.transaction_id !== options.transactionId) {
        throw new Error(
          `Deferred Credential Request: response transaction_id ` +
            `("${pending.transaction_id}") does not match sent transaction_id ` +
            `("${options.transactionId}") — spec violation`,
        );
      }
    }

    return parsedResponse;
  }
}
