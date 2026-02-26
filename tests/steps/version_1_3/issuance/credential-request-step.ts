import {
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";
import {
  createCredentialRequest,
  CredentialRequestOptionsV1_3,
  fetchCredentialResponse,
  FetchCredentialResponseOptions,
  KeyAttestationHeader,
  KeyAttestationPayload,
} from "@pagopa/io-wallet-oid4vci";
import {
  dateToSeconds,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import {
  buildCertPath,
  buildJwksPath,
  createAndSaveKeys,
  createKeys,
  loadCertificate,
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
    const unitSigner = {
      alg: "ES256",
      method: "jwk" as const,
      publicJwk: unitKey.publicKey,
    };
    const unitCertificate = await loadCertificate(
      this.config.wallet.backup_storage_path,
      buildCertPath("wallet_unit"),
      unitKey,
      `CN=${this.config.wallet.wallet_id}`,
    );

    log.info(`Generating new key pair for credential...`);
    const credentialKeyPair = this.config.issuance.save_credential
      ? await createAndSaveKeys(
          buildJwksPath(
            `${this.config.wallet.backup_storage_path}/${options.credentialIdentifier}`,
          ),
        )
      : await createKeys();

    // Generating key attestation for credentialKeyPair
    const keyAttestationHeader: KeyAttestationHeader = {
      alg: "ES256",
      kid: unitSigner.publicJwk.kid,
      typ: "key-attestation+jwt",
      x5c: [unitCertificate],
    };
    const keyAttestationPayload: KeyAttestationPayload = {
      attested_keys: [credentialKeyPair.publicKey],
      exp: dateToSeconds(new Date(Date.now() + 24 * 60 * 60 * 1000 * 365)),
      iat: dateToSeconds(new Date()),
      iss: unitKey.publicKey.kid,
      key_storage: ["iso_18045_basic"],
      status: {
        status_list: {
          idx: 0,
          uri: "http://example.com",
        },
      },
      user_authentication: ["iso_18045_basic"],
    };
    const keyAttestation = await signJwtCallback([unitKey.privateKey])(
      unitSigner,
      {
        header: keyAttestationHeader,
        payload: keyAttestationPayload,
      },
    );

    return await this.execute<CredentialRequestExecuteResponse>(async () => {
      log.info(`Creating the Credential Request...`);
      const createCredentialRequestOptions: CredentialRequestOptionsV1_3 = {
        callbacks: {
          signJwt: signJwtCallback([credentialKeyPair.privateKey]),
        },
        clientId: options.clientId,
        config: new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
        }),
        credential_identifier: options.credentialIdentifier,
        issuerIdentifier: this.config.issuance.url,
        keyAttestation: keyAttestation.jwt,
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
        signer: unitSigner,
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
