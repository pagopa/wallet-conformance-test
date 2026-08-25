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
  return resolveWalletProviderBaseUrl({ port });
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
 * Resolves the public Wallet Provider entity identifier.
 *
 * The configured URL identifies the Wallet Provider in federation. It is
 * intentionally independent from the local listener address and port.
 */
export function resolveWalletProviderBaseUrl(
  wallet: WalletProviderUrlConfig,
): string {
  const configuredUrl = wallet.wallet_provider_base_url;
  return configuredUrl
    ? configuredUrl.replace(/\/+$/, "")
    : `https://${LOCAL_WP_HOST}:${wallet.port}`;
}
