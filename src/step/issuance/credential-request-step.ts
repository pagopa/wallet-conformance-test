import {
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  createCredentialRequest,
  CredentialRequestOptions,
  CredentialResponse,
  fetchCredentialResponse,
  FetchCredentialResponseOptions,
} from "@pagopa/io-wallet-oid4vci";

import { 
  createAndSaveKeys, 
  createKeys, 
  partialCallbacks, 
  signJwtCallback 
} from "@/logic";
import { StepFlow, StepResult } from "@/step";
import { AttestationResponse, KeyPair } from "@/types";

export type CredentialRequestExecuteResponse = CredentialResponse;

export type CredentialRequestResponse = StepResult & {
  response?: CredentialResponse & {
    credentialKeyPair?: KeyPair;
  };
};

export interface CredentialRequestStepOptions {
  /**
   * Access Token fetched during the TokenRequestStep
   */
  accessToken: string;

  /**
   * Base URL of the issuer.
   */
  baseUrl: string;

  /**
   * Client ID of the OAuth2 Client,
   * if not provided, the client ID will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  credentialIdentifier: string;

  /**
   * Credential Request Endpoint URL,
   * if not provided, the endpoint will be loaded from the issuer metadata
   */
  credentialRequestEndpoint: string;

  /**
   * Nonce fetched during the NonceRequestStep
   */
  nonce: string;

  /**
   * Wallet Attestation used to authenticate the client,
   * if not provided, the attestation will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

export class CredentialRequestDefaultStep extends StepFlow {
  tag = "CREDENTIAL_REQUEST";

  async run(
    options: CredentialRequestStepOptions,
  ): Promise<CredentialRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Credential Request Step`);

    const { unitKey } = options.walletAttestation;

    log.info(`Generating new key pair for credential...`);
    const credentialKeyPair = this.config.issuance.save_credential 
      ? await createAndSaveKeys(`${this.config.wallet.backup_storage_path}/${options.credentialIdentifier}_jwks`)
      : await createKeys();

    return await this.execute<CredentialRequestExecuteResponse>(async () => {
      log.info(`Creating the Credential Request...`);
      const createCredentialRequestOptions: CredentialRequestOptions = {
        callbacks: {
          signJwt: signJwtCallback([credentialKeyPair.privateKey]),
        },
        clientId: options.clientId,
        credential_identifier: options.credentialIdentifier,
        issuerIdentifier: options.baseUrl,
        nonce: options.nonce,
        signer: {
          alg: "ES256",
          method: "jwk",
          publicJwk: credentialKeyPair.publicKey,
        },
      };
      const credentialRequest = await createCredentialRequest(
        createCredentialRequestOptions,
      );

      log.info(`Generating DPoP...`);
      const createTokenDPoPOptions: CreateTokenDPoPOptions = {
        accessToken: options.accessToken,
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([unitKey.privateKey]),
        },
        signer: {
          alg: "ES256",
          method: "jwk",
          publicJwk: unitKey.publicKey,
        },
        tokenRequest: {
          method: "POST",
          url: options.credentialRequestEndpoint,
        },
      };
      const credentialDPoP = await createTokenDPoP(createTokenDPoPOptions);

      log.info(
        `Fetching Credential Response from ${options.credentialRequestEndpoint}`,
      );
      log.debug(
        `Credential request credentialIdentifier: ${options.credentialIdentifier}`,
      );
      const fetchCredentialResponseOptions: FetchCredentialResponseOptions = {
        accessToken: options.accessToken,
        callbacks: {
          fetch,
        },
        credentialEndpoint: options.credentialRequestEndpoint,
        credentialRequest,
        dPoP: credentialDPoP.jwt,
      };
      const credentialResponse = await fetchCredentialResponse(
        fetchCredentialResponseOptions,
      );

      return {
        credentialKeyPair,
        ...credentialResponse,
      };
    });
  }
}
