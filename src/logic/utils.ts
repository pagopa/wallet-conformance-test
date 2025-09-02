import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { parse } from "ini";
import { BinaryLike, createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import { Config } from "@/types";

import { verifyJwt } from ".";

export const partialCallbacks: Partial<CallbackContext> = {
  fetch,
  generateRandom: randomBytes,
  hash: (data: BinaryLike, alg: string) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};

/**
 * Loads and parses the configuration from a specified INI file.
 *
 * @param fileName The path to the INI configuration file.
 * @returns The parsed configuration object.
 */
export function loadConfig(fileName: string): Config {
  const textConfig = readFileSync(fileName, "utf-8");

  return parse(textConfig) as Config;
}
