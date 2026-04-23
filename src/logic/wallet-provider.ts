import { LOCAL_WP_HOST } from "@/servers/wp-server";
import { Config, KeyPair } from "@/types";

import { loadCertificate } from "./pem";

/**
 * Loads (or lazily generates and caches on disk) an X.509 certificate for the
 * wallet provider key pair, suitable for use in
 * WalletAttestationOptionsV1_3.signer.x5c.
 *
 * Follows the same lazy-cache pattern as loadCertificate /
 * loadTAJwksWithSelfSignedX5c.
 *
 * @param wallet - The wallet configuration section from Config
 * @param providerKeyPair - The provider key pair loaded from backup_storage_path
 * @returns A non-empty tuple of base64-DER certificate strings: [leaf, ...chain]
 */
export async function loadWalletProviderCertificate(
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
): Promise<[string, ...string[]]> {
  const providerDomain = LOCAL_WP_HOST;
  const cert = await loadCertificate(
    wallet.backup_storage_path,
    "wallet_provider_cert",
    providerKeyPair,
    `CN=${providerDomain}`,
  );
  return [cert];
}
