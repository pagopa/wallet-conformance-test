import { Config } from "@/types";

export const LOCAL_TA_HOST = "trust-anchor.wct.example.org";
export const LOCAL_TA_BASE_URL = `https://${LOCAL_TA_HOST}`;

/**
 * Returns the Trust Anchor base URL to use for wallet attestation.
 *
 * @param config - The Trust Anchor configuration
 * @returns The Trust Anchor base URL
 */
export function resolveTrustAnchorBaseUrl(
  config: Config["trust_anchor"],
): string {
  return `${LOCAL_TA_BASE_URL}:${config.port}`;
}
