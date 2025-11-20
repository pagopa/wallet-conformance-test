import { parseMdoc } from "@/logic";
import { SDJwt } from "@sd-jwt/core";
import { readdirSync, readFileSync } from "node:fs";

import { Credential } from "@/types";

/**
 * Loads credentials from a specified directory, verifies them, and returns the valid ones.
 * The function supports both SD-JWT and MDOC credential formats.
 *
 * @param path - The directory path where credential files are located.
 * @param types - An array of credential type names, used to filter and identify credentials.
 * @returns A promise that resolves to a record object where keys are the credential filenames
 *          and values are the credential data (content of SD-JWT or MDOC).
 */
export async function loadCredentials(
  path: string,
  types: string[],
  onIgnoreError: (msg: string) => void,
): Promise<Record<string, Credential>> {
  const files = readdirSync(path);
  const credentials: Record<string, Credential> = {};

  for (const file of files) {
    // Skip if the file is not a recognized credential type
    if (!file || !types.find((name) => name === file)) {
      onIgnoreError(
        `current issuer does not support '${file}' credential type`,
      );
      continue;
    }

    // First, attempt to parse the credential as a SD-JWT
    try {
      const credential = readFileSync(`${path}/${file}`, "utf-8");
      const jwt = await SDJwt.extractJwt(credential);

      credentials[file] = {
        credential: jwt,
        typ: "dc+sd-jwt",
      };
      continue; // Move to the next file
    } catch (e) {
      const err = e as Error;
      onIgnoreError(
        `${file} was not a valid sd-jwt credential: ${err.message}`,
      );
    }

    // If SD-JWT verification fails, attempt to parse it as an MDOC
    try {
      const credential = readFileSync(`${path}/${file}`, "utf-8");
      const mdoc = parseMdoc(Buffer.from(credential, "base64url"));

      // If validation is successful, add it to the credentials record
      credentials[file] = {
        credential: mdoc,
        typ: "mso_mdoc",
      };
    } catch (e) {
      const err = e as Error;
      onIgnoreError(`${file} was not a valid mdoc credential: ${err.message}`);
    }
  }

  return credentials;
}
