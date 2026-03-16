import {
  WalletAttestationOptions,
  WalletAttestationOptionsV1_0,
  WalletAttestationOptionsV1_3,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import type { AttestationResponse, Config } from "@/types";

import {
  buildAttestationPath,
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  getTrustMarks,
  loadJsonDumps,
  loadJwks,
  loadWalletProviderCertificate,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import { fetchExternalSubordinateStatement } from "@/trust-anchor/external-ta-registration";
import {
  isExternalTrustAnchor,
  resolveTrustAnchorBaseUrl,
} from "@/trust-anchor/trust-anchor-resolver";

/**
 * Loads a wallet attestation from the filesystem.
 * If the attestation is not found, a new one is generated and saved.
 *
 * @param options - Configuration options for loading or generating the attestation
 * @param options.trustAnchor - Trust anchor configuration (local or external TA URL, port, etc.)
 * @param options.trust - Federation trust configuration, including trust anchor JWKS paths
 * @param options.wallet - Wallet configuration (provider URL, version, storage paths, etc.)
 * @param options.network - Network configuration used for external trust anchor requests
 * @returns A promise that resolves to the wallet attestation response.
 */
export const loadAttestation = async (options: {
  trustAnchor: Config["trust_anchor"];
  trust: Config["trust"];
  wallet: Config["wallet"];
  network: Config["network"];
}): Promise<AttestationResponse> => {
  const { trustAnchor, trust, wallet, network } = options;

  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(trustAnchor);

  const attestationBasePath = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_version}`;

  const attestationPath = buildAttestationPath(
    wallet,
    trustAnchor.external_ta_url,
  );

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
    const taEntityConfiguration = isExternalTrustAnchor(trustAnchor.external_ta_url)
      ? await fetchExternalSubordinateStatement(
          trustAnchor.external_ta_url,
          wallet.wallet_provider_base_url,
          network,
        )
      : await createSubordinateTrustAnchorMetadata({
          entityPublicJwk: providerKeyPair.publicKey,
          federationTrustAnchor: trust,
          sub: wallet.wallet_provider_base_url,
          trustAnchorBaseUrl: trustAnchorBaseUrl,
          walletVersion: wallet.wallet_version,
        });

    const trust_marks = await getTrustMarks(
      trustAnchorBaseUrl,
      trust.federation_trust_anchors_jwks_path,
      trustAnchorBaseUrl,
    );
    const placeholders = {
      public_key: providerKeyPair.publicKey,
      trust_anchor_base_url: trustAnchorBaseUrl,
      trust_marks,
      wallet_name: wallet.wallet_name,
      wallet_provider_base_url: wallet.wallet_provider_base_url,
    };
    const wpClaims = loadJsonDumps(
      "wallet_provider_metadata.json",
      placeholders,
      wallet.wallet_version,
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

    let attestationOptions: WalletAttestationOptions;

    switch (wallet.wallet_version) {
      case ItWalletSpecsVersion.V1_0: {
        const options: WalletAttestationOptionsV1_0 = {
          authenticatorAssuranceLevel: "substantial",
          callbacks,
          dpopJwkPublic: unitKeyPair.publicKey,
          issuer: wallet.wallet_provider_base_url,
          signer: {
            alg: providerKeyPair.privateKey.alg || "ES256",
            kid: providerKeyPair.privateKey.kid,
            method: "federation",
            trustChain: [wpEntityConfiguration, taEntityConfiguration],
          },
          walletLink: `${wallet.wallet_provider_base_url}/wallet`,
          walletName: wallet.wallet_name,
        };
        attestationOptions = options;
        break;
      }
      case ItWalletSpecsVersion.V1_3: {
        const x5c = await loadWalletProviderCertificate(
          wallet,
          providerKeyPair,
        );
        const options: WalletAttestationOptionsV1_3 = {
          callbacks,
          dpopJwkPublic: unitKeyPair.publicKey,
          issuer: wallet.wallet_provider_base_url,
          signer: {
            alg: providerKeyPair.privateKey.alg || "ES256",
            kid: providerKeyPair.privateKey.kid,
            method: "x5c",
            trustChain: [wpEntityConfiguration, taEntityConfiguration],
            x5c,
          },
          walletLink: `${wallet.wallet_provider_base_url}/wallet`,
          walletName: wallet.wallet_name,
        };
        attestationOptions = options;
        break;
      }
      default:
        throw new Error(
          `unimplemented wallet_version for attestation: ${wallet.wallet_version}`,
        );
    }
    const provider = new WalletProvider(
      new IoWalletSdkConfig({
        itWalletSpecsVersion: wallet.wallet_version,
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
