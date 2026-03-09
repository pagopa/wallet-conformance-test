import { readFileSync, writeFileSync } from "node:fs";

import { createFederationMetadata, loadJsonDumps, loadJwks } from "@/logic";
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

  let lastError: Error | undefined;
  for (let attempt = 0; attempt < network.max_retries; attempt++) {
    try {
      const response = await fetch(fetchUrl, {
        headers: {
          Accept: "application/entity-statement+jwt",
          ...(network.user_agent ? { "User-Agent": network.user_agent } : {}),
        },
        method: "GET",
        signal: AbortSignal.timeout(network.timeout * 1000),
      });

      if (!response.ok) {
        throw new Error(
          `External TA /fetch returned HTTP ${response.status} for sub=${wpBaseUrl}`,
        );
      }

      return await response.text();
    } catch (e) {
      lastError = e as Error;
      if (lastError.name === "TimeoutError") {
        throw new Error(
          `External TA /fetch timed out after ${network.timeout}s`,
        );
      }
    }
  }

  throw new Error(
    `External TA /fetch failed after ${network.max_retries} attempts: ${lastError?.message}`,
  );
}

