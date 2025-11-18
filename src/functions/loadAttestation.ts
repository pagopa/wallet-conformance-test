import {
  WalletAttestationOptions,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import type { AttestationResponse, Config } from "@/types";

import {
  loadJsonDumps,
  loadJwks,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  createTrustAnchorMetadata,
} from "@/logic/federation-metadata";

/**
 * Loads a wallet attestation from the filesystem.
 * If the attestation is not found, a new one is generated and saved.
 *
 * @param wallet The wallet configuration.
 * @returns A promise that resolves to the wallet attestation JWT.
 */
export const loadAttestation = async (options: {
  trustAnchorJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"];
  wallet: Config["wallet"];
}): Promise<AttestationResponse> => {
  const { trustAnchorJwksPath, wallet } = options;
  const attestationPath = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_id}`;

  try {
    if (!existsSync(wallet.wallet_attestations_storage_path))
      mkdirSync(wallet.wallet_attestations_storage_path, {
        recursive: true,
      });

    if (!existsSync(wallet.backup_storage_path))
      mkdirSync(wallet.backup_storage_path, {
        recursive: true,
      });
  } catch (e) {
    const err = e as Error;
    throw new Error(
      `unable to find or create necessary directories: ${err.message}`,
    );
  }

  const providerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    "/wallet_provider_jwks",
  );
  const unitKeyPair = await loadJwks(
    wallet.backup_storage_path,
    "/wallet_unit_jwks",
  );

  try {
    return {
      attestation: readFileSync(attestationPath, "utf-8"),
      created: false,
      providerKey: providerKeyPair,
      unitKey: unitKeyPair,
    };
  } catch {
    if (!providerKeyPair.privateKey.kid)
      throw new Error("invalid key pair: kid missing");

    if (providerKeyPair.privateKey.kid !== providerKeyPair.publicKey.kid)
      throw new Error("invalid key pair: kid does not match");

    const taEntityConfiguration = await createSubordinateTrustAnchorMetadata({
      entityPublicJwk: providerKeyPair.publicKey,
      federationTrustAnchorsJwksPath: trustAnchorJwksPath,
      sub: wallet.wallet_provider_base_url,
    });
    const placeholders = {
      publicKey: providerKeyPair.publicKey,
      trust_anchor_base_url: "https://127.0.0.1:3001",
      wallet_provider_base_url: wallet.wallet_provider_base_url,
    };
    const wpClaims = loadJsonDumps(
      "wallet_provider_metadata.json",
      placeholders,
    );
    const wpEntityConfiguration = await createFederationMetadata({
      claims: wpClaims,
      entityPublicJwk: providerKeyPair.publicKey,
      signedJwks: providerKeyPair,
    });

    const attestationOptions: WalletAttestationOptions = {
      dpopJwkPublic: unitKeyPair.publicKey,
      issuer: wallet.wallet_provider_base_url,
      signer: {
        trustChain: [wpEntityConfiguration, taEntityConfiguration],
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
      providerKey: providerKeyPair,
      unitKey: unitKeyPair,
    };
  }
};
