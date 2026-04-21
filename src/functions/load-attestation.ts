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
import { SDJwt } from "@sd-jwt/core";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

import { AttestationExpiredError, TrustChainExpiredError } from "@/errors";
import {
  buildAttestationPath,
  buildJwksPath,
  CLOCK_SKEW_TOLERANCE_MS,
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  ensureDir,
  getTrustMarks,
  hasTrustChainExpired,
  loadJsonDumps,
  loadJwks,
  loadWalletProviderCertificate,
  partialCallbacks,
  signJwtCallback,
  validateProviderKeyPair,
} from "@/logic";
import { getLocalWpBaseUrl } from "@/servers/wp-server";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";
import {
  type AttestationResponse,
  type Config,
  type KeyPair,
  zTrustChain,
} from "@/types";

const resolveTaEntityConfiguration = (
  trust: Config["trust"],
  providerPublicKey: KeyPair["publicKey"],
  walletProviderBaseUrl: string,
  trustAnchorBaseUrl: string,
  walletVersion: Config["wallet"]["wallet_version"],
): Promise<string> =>
  createSubordinateTrustAnchorMetadata({
    entityPublicJwk: providerPublicKey,
    federationTrustAnchor: trust,
    sub: walletProviderBaseUrl,
    trustAnchorBaseUrl,
    walletVersion,
  });

interface LoadAttestationOptions {
  network: Config["network"];
  trust: Config["trust"];
  trustAnchor: Config["trust_anchor"];
  wallet: Config["wallet"];
}

export const buildWpEntityConfiguration = async (
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
    wallet_provider_base_url: getLocalWpBaseUrl(wallet.port),
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
  const wpBaseUrl = getLocalWpBaseUrl(wallet.port);
  const commonOptions = {
    callbacks,
    dpopJwkPublic: unitPublicKey,
    issuer: wpBaseUrl,
    walletLink: `${wpBaseUrl}/wallet`,
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
  { trust, trustAnchor, wallet }: LoadAttestationOptions,
  providerKeyPair: KeyPair,
  unitKeyPair: KeyPair,
  attestationPath: string,
): Promise<string> => {
  validateProviderKeyPair(providerKeyPair);

  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(trustAnchor);

  const [taEntityConfiguration, wpEntityConfiguration] = await Promise.all([
    resolveTaEntityConfiguration(
      trust,
      providerKeyPair.publicKey,
      getLocalWpBaseUrl(wallet.port),
      trustAnchorBaseUrl,
      wallet.wallet_version,
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
 * @param options.trustAnchor - Trust anchor configuration
 * @param options.trust - Federation trust configuration, including trust anchor JWKS paths
 * @param options.wallet - Wallet configuration (provider URL, version, storage paths, etc.)
 * @returns A promise that resolves to the wallet attestation response.
 */
export const loadAttestation = async (
  options: LoadAttestationOptions,
): Promise<AttestationResponse> => {
  const { wallet } = options;

  ensureDir(
    `${wallet.wallet_attestations_storage_path}/${wallet.wallet_version}`,
  );
  ensureDir(wallet.backup_storage_path);

  const [providerKeyPair, unitKeyPair] = await Promise.all([
    loadJwks(wallet.backup_storage_path, buildJwksPath("wallet_provider")),
    loadJwks(wallet.backup_storage_path, buildJwksPath("wallet_unit")),
  ]);

  const attestationPath = buildAttestationPath(wallet);

  if (existsSync(attestationPath)) {
    try {
      const attestation = readFileSync(attestationPath, "utf-8");
      const attestationJwt = await SDJwt.extractJwt(attestation);
      // Since, at version 0.17.0, the SDJwt.extractJwt method dosn't check for WIA expiration,
      // it must be done manually
      const exp = attestationJwt.payload?.exp;
      if (
        !exp ||
        typeof exp !== "number" ||
        exp * 1000 < Date.now() - CLOCK_SKEW_TOLERANCE_MS
      )
        throw new AttestationExpiredError("attestation expired");
      const trust_chain = zTrustChain.safeParse(
        attestationJwt.header?.trust_chain,
      );
      if (trust_chain.success && hasTrustChainExpired(trust_chain.data))
        throw new TrustChainExpiredError("attestation trust_chain expired");

      return {
        attestation,
        created: false,
        providerKey: providerKeyPair,
        unitKey: unitKeyPair,
      };
    } catch {
      // If the existing attestation cannot be read (missing/unreadable/corrupt),
      // fall back to generating a new one.
    }
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
