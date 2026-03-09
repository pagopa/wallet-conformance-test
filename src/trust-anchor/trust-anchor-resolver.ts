import { Config } from "@/types";

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
 * @param config - The full application configuration
 * @returns The Trust Anchor base URL
 */
export function resolveTrustAnchorBaseUrl(config: Config): string {
  if (config.trust_anchor.external_ta_url) {
    return config.trust_anchor.external_ta_url;
  }
  return `https://127.0.0.1:${config.trust_anchor.port}`;
}

/**
 * Returns `true` when an external Trust Anchor URL is configured.
 *
 * @param config - The full application configuration
 */
export function isExternalTrustAnchor(config: Config): boolean {
  return !!config.trust_anchor.external_ta_url;
}
