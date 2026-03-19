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
import { existsSync, readFileSync, writeFileSync } from "node:fs";

import type { AttestationResponse, Config, KeyPair } from "@/types";

import {
  buildAttestationPath,
  createFederationMetadata,
  ensureDir,
  getTrustMarks,
  loadJsonDumps,
  loadJwks,
  loadWalletProviderCertificate,
  partialCallbacks,
  resolveTaEntityConfiguration,
  signJwtCallback,
} from "@/logic";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";

interface LoadAttestationOptions {
  network: Config["network"];
  trust: Config["trust"];
  trustAnchor: Config["trust_anchor"];
  wallet: Config["wallet"];
}

const validateProviderKeyPair = (keyPair: KeyPair): void => {
  if (!keyPair.privateKey.kid) {
    throw new Error("invalid key pair: kid missing");
  }
  if (keyPair.privateKey.kid !== keyPair.publicKey.kid) {
    throw new Error("invalid key pair: kid does not match");
  }
};

const buildWpEntityConfiguration = async (
  trust: Config["trust"],
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
  trustAnchorBaseUrl: string,
): Promise<string> => {
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
  return createFederationMetadata({
    claims: wpClaims,
    entityPublicJwk: providerKeyPair.publicKey,
    signedJwks: providerKeyPair,
  });
};

const buildAttestationOptions = async (
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
  unitPublicKey: KeyPair["publicKey"],
  trustChain: [string, string],
): Promise<WalletAttestationOptions> => {
  const callbacks = {
    ...partialCallbacks,
    signJwt: signJwtCallback([providerKeyPair.privateKey]),
  };
  const commonOptions = {
    callbacks,
    dpopJwkPublic: unitPublicKey,
    issuer: wallet.wallet_provider_base_url,
    walletLink: `${wallet.wallet_provider_base_url}/wallet`,
    walletName: wallet.wallet_name,
  };
  const signerBase = {
    alg: providerKeyPair.privateKey.alg ?? "ES256",
    kid: providerKeyPair.privateKey.kid,
  };

  switch (wallet.wallet_version) {
    case ItWalletSpecsVersion.V1_0: {
      const attestationOptions: WalletAttestationOptionsV1_0 = {
        ...commonOptions,
        authenticatorAssuranceLevel: "substantial",
        signer: { ...signerBase, method: "federation", trustChain },
      };
      return attestationOptions;
    }
    case ItWalletSpecsVersion.V1_3: {
      const x5c = await loadWalletProviderCertificate(wallet, providerKeyPair);
      const attestationOptions: WalletAttestationOptionsV1_3 = {
        ...commonOptions,
        signer: { ...signerBase, method: "x5c", trustChain, x5c },
      };
      return attestationOptions;
    }
    default:
      throw new Error(
        `unimplemented wallet_version for attestation: ${wallet.wallet_version}`,
      );
  }
};

const createAttestation = async (
  { network, trust, trustAnchor, wallet }: LoadAttestationOptions,
  providerKeyPair: KeyPair,
  unitKeyPair: KeyPair,
  attestationPath: string,
): Promise<string> => {
  validateProviderKeyPair(providerKeyPair);

  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(trustAnchor);

  const [taEntityConfiguration, wpEntityConfiguration] = await Promise.all([
    resolveTaEntityConfiguration(
      trustAnchor,
      trust,
      providerKeyPair.publicKey,
      wallet.wallet_provider_base_url,
      trustAnchorBaseUrl,
      wallet.wallet_version,
      network,
    ),
    buildWpEntityConfiguration(
      trust,
      wallet,
      providerKeyPair,
      trustAnchorBaseUrl,
    ),
  ]);

  const attestationOptions = await buildAttestationOptions(
    wallet,
    providerKeyPair,
    unitKeyPair.publicKey,
    [wpEntityConfiguration, taEntityConfiguration],
  );

  const provider = new WalletProvider(
    new IoWalletSdkConfig({ itWalletSpecsVersion: wallet.wallet_version }),
  );
  const attestation =
    await provider.createItWalletAttestationJwt(attestationOptions);

  writeFileSync(attestationPath, attestation);
  return attestation;
};

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
export const loadAttestation = async (
  options: LoadAttestationOptions,
): Promise<AttestationResponse> => {
  const { trustAnchor, wallet } = options;

  ensureDir(
    `${wallet.wallet_attestations_storage_path}/${wallet.wallet_version}`,
  );
  ensureDir(wallet.backup_storage_path);

  const [providerKeyPair, unitKeyPair] = await Promise.all([
    loadJwks(wallet.backup_storage_path, "/wallet_provider_jwks"),
    loadJwks(wallet.backup_storage_path, "/wallet_unit_jwks"),
  ]);

  const attestationPath = buildAttestationPath(
    wallet,
    trustAnchor.external_ta_url,
  );

  if (existsSync(attestationPath)) {
    return {
      attestation: readFileSync(attestationPath, "utf-8"),
      created: false,
      providerKey: providerKeyPair,
      unitKey: unitKeyPair,
    };
  }

  const attestation = await createAttestation(
    options,
    providerKeyPair,
    unitKeyPair,
    attestationPath,
  );

  return {
    attestation,
    created: true,
    providerKey: providerKeyPair,
    unitKey: unitKeyPair,
  };
};
