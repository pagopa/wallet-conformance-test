import {
  WalletAttestationOptions,
  WalletProvider,
} from "@pagopa/io-wallet-oid4vci";
import { SignJWT } from "jose";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import type { AttestationResponse, Config } from "@/types";

import {
  generateKey,
  loadJwks,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";

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
    const trustChain = await new SignJWT({
      jwks: {
        keys: [providerKeyPair.publicKey],
      },
      metadata: {
        wallet_provider: {
          jwks: {
            keys: [providerKeyPair.publicKey],
          },
        },
      },
    })
      .setProtectedHeader({ alg: "ES256" })
      .setAudience(wallet.wallet_provider_base_url)
      .setIssuer(wallet.wallet_provider_base_url)
      .setSubject(providerKeyPair.publicKey.kid || "")
      .setExpirationTime("24h")
      .setIssuedAt()
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
      providerKey: providerKeyPair,
      unitKey: unitKeyPair,
    };
  }
}
