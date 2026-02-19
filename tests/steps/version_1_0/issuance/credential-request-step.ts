import {
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  createCredentialRequest,
  CredentialRequestOptionsV1_0,
  fetchCredentialResponse,
  FetchCredentialResponseOptions,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import {
  buildJwksPath,
  createAndSaveKeys,
  createKeys,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import {
  CredentialRequestDefaultStep,
  CredentialRequestExecuteResponse,
  CredentialRequestResponse,
  CredentialRequestStepOptions,
} from "@/step/issuance/credential-request-step";

export class CredentialRequestITWallet1_0Step extends CredentialRequestDefaultStep {
  tag = "CREDENTIAL_REQUEST";

  async run(
    options: CredentialRequestStepOptions,
  ): Promise<CredentialRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Credential Request Step`);

    const { unitKey } = options.walletAttestation;

    log.info(`Generating new key pair for credential...`);
    const credentialKeyPair = this.config.issuance.save_credential
      ? await createAndSaveKeys(
          buildJwksPath(
            `${this.config.wallet.backup_storage_path}/${options.credentialIdentifier}`,
          ),
        )
      : await createKeys();

    return await this.execute<CredentialRequestExecuteResponse>(async () => {
      log.info(`Creating the Credential Request...`);
      const createCredentialRequestOptions: CredentialRequestOptionsV1_0 = {
        callbacks: {
          signJwt: signJwtCallback([credentialKeyPair.privateKey]),
        },
        clientId: options.clientId,
        config: new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
        }),
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
