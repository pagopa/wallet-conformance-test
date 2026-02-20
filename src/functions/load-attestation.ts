import {
  CredentialRequestOptionsV1_0,
  WalletAttestationOptions,
  WalletAttestationOptionsV1_0,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import type { AttestationResponse, Config } from "@/types";

import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  loadJsonDumps,
  loadJwks,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";

/**
 * Loads a wallet attestation from the filesystem.
 * If the attestation is not found, a new one is generated and saved.
 *
 * @param options - Configuration options
 * @param options.trustAnchorJwksPath - Path to the trust anchor JWKS
 * @param options.wallet - The wallet configuration
 * @returns A promise that resolves to the wallet attestation response.
 */
export const loadAttestation = async (options: {
  trustAnchorBaseUrl: string;
  trustAnchorJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"];
  wallet: Config["wallet"];
}): Promise<AttestationResponse> => {
  const { trustAnchorBaseUrl, trustAnchorJwksPath, wallet } = options;
  const attestationBasePath = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_version ? wallet.wallet_version : ItWalletSpecsVersion.V1_0}`
  const attestationPath = `${attestationBasePath}/${wallet.wallet_id}`;

  try {
    if (!existsSync(attestationBasePath))
      mkdirSync(attestationBasePath, {
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

    //This might be moved to a step specific implementation
    const taEntityConfiguration = await createSubordinateTrustAnchorMetadata({
      entityPublicJwk: providerKeyPair.publicKey,
      federationTrustAnchorsJwksPath: trustAnchorJwksPath,
      sub: wallet.wallet_provider_base_url,
      trustAnchorBaseUrl: trustAnchorBaseUrl,
    });
    const placeholders = {
      public_key: providerKeyPair.publicKey,
      trust_anchor_base_url: trustAnchorBaseUrl,
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

    const callbacks = {
      ...partialCallbacks,
      signJwt: signJwtCallback([providerKeyPair.privateKey]),
    };

    const attestationOptions: WalletAttestationOptionsV1_0 = {
      authenticatorAssuranceLevel: "substantial",
      callbacks,
      dpopJwkPublic: unitKeyPair.publicKey,
      issuer: wallet.wallet_provider_base_url,
      signer: {
        alg: providerKeyPair.privateKey.alg || "ES256",
        kid: providerKeyPair.privateKey.kid,
        method: "federation" as const,
        trustChain: [wpEntityConfiguration, taEntityConfiguration],
      },
      walletLink: `${wallet.wallet_provider_base_url}/wallet`,
      walletName: wallet.wallet_name,
    };
    const provider = new WalletProvider(
      new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      }),
    );
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
