import {
  createFederationMetadata,
  fetchWithRetries,
  loadJsonDumps,
  loadJwks,
} from "@/logic";
import { Config } from "@/types";

/**
 * Fetches the Subordinate Statement (entity statement) for the Wallet Provider
 * from the external Trust Anchor's `/fetch` endpoint.
 *
 * @param externalTaUrl - Base URL of the external Trust Anchor
 * @param wpBaseUrl - Wallet Provider base URL (the `sub` parameter)
 * @param network - Network configuration for timeout and retries
 * @returns The raw JWT string of the Subordinate Statement
 * @throws If the response is not `application/entity-statement+jwt` or the request fails
 */
export async function fetchExternalSubordinateStatement(
  externalTaUrl: string,
  wpBaseUrl: string,
  network: Config["network"],
): Promise<string> {
  const fetchUrl = `${externalTaUrl}/fetch?sub=${encodeURIComponent(wpBaseUrl)}`;
  let response: Response;
  try {
    ({ response } = await fetchWithRetries(fetchUrl, network, {
      headers: { Accept: "application/entity-statement+jwt" },
      method: "GET",
    }));
  } catch (e) {
    const err = e as Error;
    if (err.name === "TimeoutError") {
      throw new Error(
        `External TA /fetch timed out after ${network.timeout}s for sub=${wpBaseUrl}`,
      );
    }
    throw new Error(
      `External TA /fetch failed after ${network.max_retries} attempts for sub=${wpBaseUrl}: ${err.message}`,
    );
  }
  if (!response.ok) {
    throw new Error(
      `External TA /fetch returned HTTP ${response.status} for sub=${wpBaseUrl}`,
    );
  }
  return response.text();
}

/**
 * Registers the Wallet Provider with an external Trust Anchor before tests start.
 *
 * This function is a no-op when `config.trust_anchor.external_ta_url` is not set.
 *
 * When the external TA URL is configured, it:
 * 1. Loads the WP public key from the backup storage path.
 * 2. Optionally POSTs the WP Entity Configuration JWT to the onboarding URL
 *    (if `external_ta_onboarding_url` is set). HTTP 409 is treated as idempotent success.
 * 3. Smoke-checks that `GET <external_ta_url>/fetch?sub=<wp_base_url>` returns
 *    `application/entity-statement+jwt`. Throws a descriptive error on failure,
 *    which will abort all tests.
 *
 * @param config - The full application configuration
 */
export async function registerWithExternalTrustAnchor(
  config: Config,
): Promise<void> {
  const externalTaUrl = config.trust_anchor.external_ta_url;

  // No-op when external TA is not configured
  if (!externalTaUrl) {
    return;
  }

  const { wallet, network } = config;

  // Load WP public key pair
  const providerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    "/wallet_provider_jwks",
  );

  // Build WP Entity Configuration JWT
  const placeholders = {
    public_key: providerKeyPair.publicKey,
    trust_anchor_base_url: externalTaUrl,
    wallet_name: wallet.wallet_name,
    wallet_provider_base_url: wallet.wallet_provider_base_url,
  };
  const wpClaims = loadJsonDumps(
    "wallet_provider_metadata.json",
    placeholders,
    wallet.wallet_version,
  );

  const wpEntityConfigurationJwt = await createFederationMetadata({
    claims: wpClaims,
    entityPublicJwk: providerKeyPair.publicKey,
    signedJwks: providerKeyPair,
  });

  // Optional: POST WP Entity Configuration to onboarding URL
  if (config.trust_anchor.external_ta_onboarding_url) {
    const onboardingUrl = config.trust_anchor.external_ta_onboarding_url;

    try {
      const { response } = await fetchWithRetries(onboardingUrl, network, {
        body: wpEntityConfigurationJwt,
        headers: {
          "Content-Type": "application/entity-statement+jwt",
        },
        method: "POST",
      });

      // HTTP 409 Conflict means the WP is already registered — treat as success
      if (!response.ok && response.status !== 409) {
        const body = await response.text().catch(() => "");
        throw new Error(
          `External TA onboarding POST to ${onboardingUrl} failed with HTTP ${response.status}: ${body}`,
        );
      }
    } catch (e) {
      const err = e as Error;
      throw new Error(
        `Failed to POST WP Entity Configuration to external TA onboarding endpoint ${onboardingUrl}: ${err.message}`,
      );
    }
  }

  // Smoke-check: verify the external TA can serve a Subordinate Statement for this WP
  const smokeCheckUrl = `${externalTaUrl}/fetch?sub=${encodeURIComponent(wallet.wallet_provider_base_url)}`;
  let smokeResponse: Response;

  try {
    const { response } = await fetchWithRetries(smokeCheckUrl, network, {
      headers: {
        Accept: "application/entity-statement+jwt",
      },
      method: "GET",
    });
    smokeResponse = response;
  } catch (e) {
    const err = e as Error;
    throw new Error(
      `External TA smoke-check failed — could not reach ${smokeCheckUrl}: ${err.message}.\n` +
        `Ensure the external Trust Anchor at ${externalTaUrl} is running and ` +
        `has the Wallet Provider registered as a subordinate.`,
    );
  }

  if (!smokeResponse.ok) {
    const body = await smokeResponse.text().catch(() => "");
    throw new Error(
      `External TA smoke-check failed — ${smokeCheckUrl} returned HTTP ${smokeResponse.status}.\n` +
        `Response: ${body}\n` +
        `Ensure the Wallet Provider (${wallet.wallet_provider_base_url}) is registered ` +
        `as a subordinate under the external Trust Anchor at ${externalTaUrl}.`,
    );
  }

  const contentType = smokeResponse.headers.get("content-type") ?? "";
  if (!contentType.includes("application/entity-statement+jwt")) {
    throw new Error(
      `External TA smoke-check failed — ${smokeCheckUrl} returned unexpected content-type '${contentType}'. ` +
        `Expected 'application/entity-statement+jwt'.`,
    );
  }
}
