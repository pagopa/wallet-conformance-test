import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { parse } from "ini";
import { BinaryLike, createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import { verifyJwt } from ".";

export const partialCallbacks: Partial<CallbackContext> = {
  fetch,
  generateRandom: randomBytes,
  hash: (data: BinaryLike, alg: string) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};
import { Config, configSchema } from "@/types";
import { FetchWithRetriesResponse } from "@/types/FetchWithRetriesResponse";

export async function fetchWithRetries(
  url: Request | string | URL,
  network: Config["network"],
): Promise<FetchWithRetriesResponse> {
  for (let attempts = 0; attempts < network.max_retries; attempts++) {
    try {
      const response = await fetch(url, {
        headers: {
          "User-Agent": network.user_agent,
        },
        method: "GET",
        signal: AbortSignal.timeout(network.timeout * 1000),
      });

      return { attempts, response };
    } catch (e) {
      const err = e as Error;
      if (err.name === "TimeoutError")
        throw new Error(`Request timed out: aborting`);
    }
  }

  throw new Error(`Request failed with no retries left: aborting`);
}

/**
 * Loads and parses the configuration from a specified INI file.
 *
 * @param fileName The path to the INI configuration file.
 * @returns The parsed configuration object.
 */
export function loadConfig(fileName: string): Config {
  const textConfig = readFileSync(fileName, "utf-8");
  const parsed = configSchema.parse(parse(textConfig));

  return parsed;
}
