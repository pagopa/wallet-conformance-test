import {
  WalletAttestationOptions,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import { SignJWT } from "jose";
import { readFileSync, writeFileSync } from "node:fs";

import type { AttestationResponse, Config } from "@/types";

import { generateKey, partialCallbacks, signJwtCallback } from "@/logic";

/**
 * Loads a wallet attestation from the filesystem.
 * If the attestation is not found, a new one is generated and saved.
 *
 * @param wallet The wallet configuration.
 * @returns A promise that resolves to the wallet attestation JWT.
 */
export async function loadAttestation(
  wallet: Config["wallet"],
): Promise<AttestationResponse> {
  const attestationPath = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_id}`;

  try {
    return {
      attestation: readFileSync(attestationPath, "utf-8"),
      created: false,
    };
  } catch {
    const providerKeyPair = await generateKey(
      `${wallet.backup_storage_path}/wallet_provider_jwks`,
    );
    const unitKeyPair = await generateKey(
      `${wallet.backup_storage_path}/wallet_unit_jwks`,
    );

    const trustChain = await new SignJWT({
      jwks: {
        keys: [providerKeyPair.publicKey],
      },
    })
      .setProtectedHeader({ alg: "ES256" })
      .sign(providerKeyPair.privateKey);

    if (!providerKeyPair.privateKey.kid)
      throw new Error("invalid key pair: kid missing");

    if (providerKeyPair.privateKey.kid !== providerKeyPair.publicKey.kid)
      throw new Error("invalid key pair: kid does not match");

    const attestationOptions: WalletAttestationOptions = {
      dpopJwkPublic: unitKeyPair.publicKey,
      issuer: wallet.wallet_provider_base_url,
      signer: {
        trustChain: [trustChain],
        walletProviderJwkPublicKid: providerKeyPair.privateKey.kid,
      },
      walletLink: `${wallet.wallet_provider_base_url}/wallet`,
      walletName: wallet.wallet_name,
    };
    const callbacks = {
      ...partialCallbacks,
      signJwt: signJwtCallback([providerKeyPair.privateKey]),
    };
    const provider = new WalletProvider({ callbacks });
    const attestation =
      await provider.createItWalletAttestationJwt(attestationOptions);
    writeFileSync(attestationPath, attestation);

    return {
      attestation,
      created: true,
    };
  }
}
