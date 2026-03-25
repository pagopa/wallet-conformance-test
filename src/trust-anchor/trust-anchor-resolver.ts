import { Config } from "@/types";

export const LOCAL_TA_BASE_URL = "https://trust-anchor.wct.it";

/**
 * Returns `true` when an external Trust Anchor URL is configured.
 *
 * @param external_ta_url - The external Trust Anchor URL, if configured
 */
export function isExternalTrustAnchor(
  external_ta_url?: string,
): external_ta_url is string {
  return !!external_ta_url;
}

/**
 * Returns the Trust Anchor base URL to use for wallet attestation.
 *
 * When `external_ta_url` is configured, the external TA is used for the
 * wallet provider trust chain. Otherwise, the local TA server running on
 * localhost is used.
 *
 * Note: the local TA is always used for the mock PID issuer trust chain
 * regardless of this setting — callers must pass `localTrustAnchorBaseUrl`
 * explicitly to `loadCredentialsForPresentation`.
 *
 * @param config - The Trust Anchor configuration
 * @returns The Trust Anchor base URL
 */
export function resolveTrustAnchorBaseUrl(
  config: Config["trust_anchor"],
  serverPort: number,
): string {
  if (config.external_ta_url) {
    return config.external_ta_url;
  }
  return `${LOCAL_TA_BASE_URL}:${serverPort}`;
}
