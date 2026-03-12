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
 * @param config - The Trust Anchor configuration
 * @returns The Trust Anchor base URL
 */
export function resolveTrustAnchorBaseUrl(config: Config["trust_anchor"]): string {
  if (config.external_ta_url) {
    return config.external_ta_url;
  }
  return `https://127.0.0.1:${config.port}`;
}

/**
 * Returns `true` when an external Trust Anchor URL is configured.
 *
 * @param config - The Trust Anchor configuration
 */
export function isExternalTrustAnchor(config: Config["trust_anchor"]): boolean {
  return !!config.external_ta_url;
}
