import {
  buildJwksPath,
  createFederationMetadata,
  fetchWithRetries,
  loadJsonDumps,
  loadJwks,
} from "@/logic";
import { getLocalCiBaseUrl } from "@/servers/ci-server";
import { getLocalWpBaseUrl } from "@/servers/wp-server";
import { Config } from "@/types";

/**
 * Fetches the Subordinate Statement (entity statement) for the Subject (Wallet Provider or Issuer)
 * from the external Trust Anchor's `/fetch` endpoint.
 *
 * @param externalTaUrl - Base URL of the external Trust Anchor
 * @param baseUrl - Subject (Wallet Provider or Issuer) base URL (the `sub` parameter)
 * @param network - Network configuration for timeout and retries
 * @returns The raw JWT string of the Subordinate Statement
 * @throws If the response is not `application/entity-statement+jwt` or the request fails
 */
export async function fetchExternalSubordinateStatement(
  externalTaUrl: string,
  baseUrl: string,
  network: Config["network"],
): Promise<string> {
  const fetchUrl = `${externalTaUrl}/fetch?sub=${encodeURIComponent(baseUrl)}`;
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
        `External TA /fetch timed out after ${network.timeout}s for sub=${baseUrl}`,
      );
    }
    throw new Error(
      `External TA /fetch failed after ${network.max_retries} attempts for sub=${baseUrl}: ${err.message}`,
    );
  }
  if (!response.ok) {
    throw new Error(
      `External TA /fetch returned HTTP ${response.status} for sub=${baseUrl}`,
    );
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/entity-statement+jwt")) {
    throw new Error(
      `External TA /fetch returned unexpected content-type '${contentType}' for sub=${baseUrl}. ` +
        `Expected 'application/entity-statement+jwt'.`,
    );
  }
  return response.text();
}

/**
 * Registers the Wallet Provider and Credential Issuer mocked with an external Trust Anchor before tests start.
 *
 * This function is a no-op when `config.trust_anchor.external_ta_url` is not set.
 *
 * When the external TA URL is configured, it:
 * 1. Loads the WP and CI public keys from the backup storage path.
 * 2. Optionally POSTs the WP Entity Configuration JWT and CI Entity Configuration
 *    JWT to the onboarding URL (if `external_ta_onboarding_url` is set). HTTP 409 is
 *    treated as idempotent success.
 * 3. Smoke-checks that the external TA can serve a Subordinate Statement for this WP
 *    and CI by delegating to {@link fetchExternalSubordinateStatement}. Throws a
 *    descriptive error on failure, which will abort all tests.
 *
 * @remarks
 * **Provisional implementation.** The onboarding flow implemented here (POST of the
 * WP/CI Entity Configuration JWT to `external_ta_onboarding_url`) is a conceptual sketch
 * of a possible OpenID Federation Onboarding mechanism. The protocol details are not yet
 * finalised and this function is subject to breaking changes as the specification evolves.
 *
 * @param config - The full application configuration
 */
export async function registerWithExternalTrustAnchor(
  config: Pick<Config, "issuer" | "network" | "trust_anchor" | "wallet">,
): Promise<void> {
  const externalTaUrl = config.trust_anchor.external_ta_url;

  // No-op when external TA is not configured
  if (!externalTaUrl) {
    return;
  }

  const { issuer, network, wallet } = config;

  // Load WP public key pair
  const providerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    buildJwksPath("wallet_provider"),
  );

  // Build WP Entity Configuration JWT
  const wpPlaceholders = {
    public_key: providerKeyPair.publicKey,
    trust_anchor_base_url: externalTaUrl,
    wallet_name: wallet.wallet_name,
    wallet_provider_base_url: getLocalWpBaseUrl(wallet.port),
  };
  const wpClaims = loadJsonDumps(
    "wallet_provider_metadata.json",
    wpPlaceholders,
    wallet.wallet_version,
  );

  // Load CI (issuer) public key pair
  const issuerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    buildJwksPath("issuer"),
  );

  // Build CI Entity Configuration JWT
  const ciPlaceholders = {
    issuer_base_url: getLocalCiBaseUrl(issuer.port),
    public_key: issuerKeyPair.publicKey,
    trust_anchor_base_url: externalTaUrl,
  };
  const ciClaims = loadJsonDumps(
    "issuer_metadata.json",
    ciPlaceholders,
    wallet.wallet_version,
  );

  const entityConfigurationJwts = [
    {
      baseUrl: getLocalWpBaseUrl(wallet.port),
      entity: "WP",
      jwt: await createFederationMetadata({
        claims: wpClaims,
        entityPublicJwk: providerKeyPair.publicKey,
        signedJwks: providerKeyPair,
      }),
    },
    {
      baseUrl: getLocalCiBaseUrl(issuer.port),
      entity: "CI",
      jwt: await createFederationMetadata({
        claims: ciClaims,
        entityPublicJwk: issuerKeyPair.publicKey,
        signedJwks: issuerKeyPair,
      }),
    },
  ];

  // Optional: POST WP and CI Entity Configuration to onboarding URL
  if (config.trust_anchor.external_ta_onboarding_url) {
    const onboardingUrl = config.trust_anchor.external_ta_onboarding_url;

    for (const { entity, jwt } of entityConfigurationJwts) {
      try {
        const { response } = await fetchWithRetries(onboardingUrl, network, {
          body: jwt,
          headers: {
            "Content-Type": "application/entity-statement+jwt",
          },
          method: "POST",
        });

        // HTTP 409 Conflict means the Entity is already registered — treat as success
        if (!response.ok && response.status !== 409) {
          const body = await response.text().catch(() => "");
          throw new Error(
            `External TA onboarding POST to ${onboardingUrl} for entity ${entity} failed with HTTP ${response.status}: ${body}`,
          );
        }
      } catch (e) {
        const err = e as Error;
        throw new Error(
          `Failed to POST ${entity} Entity Configuration to external TA onboarding endpoint ${onboardingUrl}: ${err.message}`,
        );
      }
    }
  }

  // Smoke-check: verify the external TA can serve a Subordinate Statement for both WP and CI
  for (const { baseUrl, entity } of entityConfigurationJwts) {
    try {
      await fetchExternalSubordinateStatement(externalTaUrl, baseUrl, network);
    } catch (e) {
      const err = e as Error;
      throw new Error(
        `External TA smoke-check failed: ${err.message}\n` +
          `Ensure the ${entity} (${baseUrl}) is registered ` +
          `as a subordinate under the external Trust Anchor at ${externalTaUrl}.`,
      );
    }
  }
}
