import type { CallbackContext } from "@pagopa/io-wallet-oauth2";

import { parseWithErrorHandling } from "@pagopa/io-wallet-oid-federation";
import { parse } from "ini";
import { BinaryLike, createHash, randomBytes } from "node:crypto";
import { readFileSync, existsSync, mkdirSync } from "node:fs";

import path from "path";
import { verifyJwt } from ".";
import { generateKey } from "../logic/jwk";
import { KeyPair } from "../types";
import { Config, configSchema } from "@/types";
import { FetchWithRetriesResponse } from "@/types/FetchWithRetriesResponse";

export const partialCallbacks: Partial<CallbackContext> = {
  fetch,
  generateRandom: randomBytes,
  hash: (data: BinaryLike, alg: string) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};

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
  const parsed = parseWithErrorHandling(configSchema, parse(textConfig));

  return parsed;
}

/**
 *  Loads a JSON file from the dumps directory.
 * @param fileName The name of the JSON file to load.
 * @returns The parsed JSON object or an error message.
 */
export const loadJsonDumps = (fileName: string) => {
  const dumpsDir = path.resolve(process.cwd(), "./dumps");
  
  const filePath = path.join(dumpsDir, fileName);
  if (!existsSync(filePath)) {
    return { error: `File ${fileName} not found` };
  }
  const raw = readFileSync(filePath, "utf-8");
  try {
    return JSON.parse(raw);
  } catch {
    return { error: `Invalid JSON in ${fileName}` };
  }
}

/**
 * Loads or generates JWKS for the federation trust anchor.
 * @param federationTrustAnchorsJwksPath 
 * @returns 
 */
export async function loadJwks(
  jwksPath: string,
): Promise<KeyPair> {

  try {
    if (!existsSync(jwksPath))
      mkdirSync(jwksPath, {
        recursive: true,
      });
  } catch (e) {
    const err = e as Error;
    throw new Error(
      `unable to find or create necessary directories ${jwksPath}: ${err.message}`,
    );
  }

  try {
    const jwksData = readFileSync(
      `${jwksPath}`,
      "utf-8",
    );
    return JSON.parse(jwksData) as KeyPair;
  } catch {
    return await generateKey(`${jwksPath}`);
  }
}
