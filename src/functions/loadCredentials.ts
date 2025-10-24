import { parse } from "@auth0/mdl";
import { readdirSync, readFileSync } from "node:fs";

import { Credential } from "@/types";
import { SDJwt } from "@sd-jwt/core";

/**
 * Loads credentials from a specified directory, verifies them, and returns the valid ones.
 * The function supports both SD-JWT and MDOC credential formats.
 *
 * @param path - The directory path where credential files are located.
 * @param types - An array of credential type names, used to filter and identify credentials.
 * @param publicKey - The public key (in JWK format) used for verifying SD-JWT signatures.
 * @param caCertPath - The file path to the Certificate Authority (CA) certificate for verifying MDOC credentials.
 * @returns A promise that resolves to a record object where keys are the credential filenames
 *          and values are the credential data (string for SD-JWT, ArrayBuffer for MDOC).
 */
export async function loadCredentials(
  path: string,
  types: string[],
): Promise<Record<string, Credential>> {
  const files = readdirSync(path);
  const credentials: Record<string, Credential> = {};

  for (const file of files) {
    const fileName = file.split("/").pop();
    // Skip if the file is not a recognized credential type
    if (!fileName || !types.find((name) => name === fileName)) {
      console.error(
        `current issuer does not support ${fileName} credential type`,
      );
      continue;
    }

    // First, attempt to parse the credential as a SD-JWT
    try {
      const credential = readFileSync(`${path}/${file}`, "utf-8");
      const jwt = await SDJwt.extractJwt(credential);

      credentials[fileName] = {
        credential: jwt,
        typ: "dc+sd-jwt",
      };
      continue; // Move to the next file
    } catch (e) {
      const err = e as Error;
      console.error(
        `${file} was not a valid sd-jwt credential: ${err.message}`,
      );
    }

    // If SD-JWT verification fails, attempt to parse it as an MDOC
    try {
      const credential = readFileSync(`${path}/${file}`);
      const mdoc = parse(credential);

      // If validation is successful, add it to the credentials record
      credentials[fileName] = {
        credential: mdoc,
        typ: "mso_mdoc",
      };
    } catch (e) {
      const err = e as Error
      console.error(`${file} was not a valid mdoc credential: ${err.message}`)
    }
  }

  return credentials;
}
