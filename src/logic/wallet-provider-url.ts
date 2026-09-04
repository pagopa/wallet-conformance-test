import type { Config } from "@/types";

export const LOCAL_WP_HOST = "wallet-provider.wct.example.org";

export type WalletProviderUrlConfig = Pick<
  Config["wallet"],
  "port" | "wallet_provider_base_url"
>;

export function appendWalletProviderPath(
  baseUrl: string,
  path: string,
): string {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

export function getLocalWpBaseUrl(port: number): string {
  return resolveNormalizedWalletProviderBaseUrl({ port });
}

export function getWalletProviderBasePath(baseUrl: string): string {
  return new URL(baseUrl).pathname.replace(/\/+$/, "") || "/";
}

export function getWalletProviderCertificateSubject(baseUrl: string): string {
  return `CN=${getWalletProviderHostname(baseUrl)}`;
}

export function getWalletProviderHostname(baseUrl: string): string {
  return new URL(baseUrl).hostname;
}

/**
 * Resolves the Wallet Provider base URL for endpoint and path construction.
 */
export function resolveNormalizedWalletProviderBaseUrl(
  wallet: WalletProviderUrlConfig,
): string {
  return resolveWalletProviderEntityIdentifier(wallet).replace(/\/+$/, "");
}

/**
 * Resolves the Wallet Provider base URL for endpoint and path construction.
 *
 * @deprecated Use resolveNormalizedWalletProviderBaseUrl for URL composition
 * or resolveWalletProviderEntityIdentifier for protocol identity fields.
 */
export function resolveWalletProviderBaseUrl(
  wallet: WalletProviderUrlConfig,
): string {
  return resolveNormalizedWalletProviderBaseUrl(wallet);
}

/**
 * Resolves the Wallet Provider entity identifier exactly as configured.
 *
 * The configured URL identifies the Wallet Provider in federation. It is
 * intentionally independent from the local listener address and port.
 */
export function resolveWalletProviderEntityIdentifier(
  wallet: WalletProviderUrlConfig,
): string {
  return (
    wallet.wallet_provider_base_url ?? `https://${LOCAL_WP_HOST}:${wallet.port}`
  );
}
