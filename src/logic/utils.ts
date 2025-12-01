import type { CallbackContext } from "@pagopa/io-wallet-oauth2";

import { BinaryLike, createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "path";

import { Config, FetchWithRetriesResponse, KeyPair } from "@/types";

import { generateKey, verifyJwt } from ".";

// Re-export config loading functions
export {
  type CliOptions,
  loadConfig,
  loadConfigWithHierarchy,
} from "./config-loader";

export const partialCallbacks: Pick<
  CallbackContext,
  "fetch" | "generateRandom" | "hash" | "verifyJwt"
> = {
  fetch,
  generateRandom: randomBytes,
  hash: (data: BinaryLike, alg: string) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};

export async function fetchWithRetries(
  url: Request | string | URL,
  network: Config["network"],
  init?: RequestInit,
): Promise<FetchWithRetriesResponse> {
  for (let attempts = 0; attempts < network.max_retries; attempts++) {
    try {
      const response = await fetch(url, {
        method: "GET",
        signal: AbortSignal.timeout(network.timeout * 1000),
        ...init,
        headers: {
          "User-Agent": network.user_agent,
          ...init?.headers,
        },
      });

      return { attempts, response };
    } catch (e) {
      console.log(e);
      const err = e as Error;
      if (err.name === "TimeoutError")
        throw new Error(`Request timed out: aborting`);
    }
  }

  throw new Error(`Request failed with no retries left: aborting`);
}

/**
 *  Loads a JSON file from the dumps directory.
 * @param fileName The name of the JSON file to load.
 * @returns The parsed JSON object or an error message.
 */
export const loadJsonDumps = (
  fileName: string,
  placeholders: Record<string, object | string>,
) => {
  const dumpsDir = path.resolve(process.cwd(), "./dumps");

  const filePath = path.join(dumpsDir, fileName);
  if (!existsSync(filePath)) {
    throw new Error(`File ${fileName} not found`);
  }
  try {
    // Read the file and replace placeholders
    let raw = readFileSync(filePath, "utf-8");

    const escapeRegExp = (s: string) =>
      s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    for (const [key, value] of Object.entries(placeholders)) {
      // Create regex to match {{key}} for strings or "{{key}}" for objects
      // object values should be replaced without quotes
      const reCurly =
        typeof value === "string"
          ? new RegExp(`\\{\\{${escapeRegExp(key)}\\}\\}`, "g")
          : new RegExp(`\\"\\{\\{${escapeRegExp(key)}\\}\\}\\"`, "g");
      const valueStr =
        typeof value === "string" ? value : JSON.stringify(value);
      raw = raw.replace(reCurly, valueStr);
    }

    return JSON.parse(raw);
  } catch (e) {
    throw new Error(
      `Missing file or invalid JSON in ${fileName}: ${(e as Error).message}`,
    );
  }
};

/**
 * Loads or generates JWKS for the federation trust anchor.
 * @param jwksPath The directory path where JWKS files are stored.
 * @param filename The name of the JWKS file to load or create.
 * @returns A promise that resolves to the loaded or generated KeyPair.
 */
export async function loadJwks(
  jwksPath: string,
  filename: string,
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
    const jwksData = readFileSync(`${jwksPath}/${filename}`, "utf-8");
    return JSON.parse(jwksData) as KeyPair;
  } catch {
    return await generateKey(`${jwksPath}/${filename}`);
  }
}
