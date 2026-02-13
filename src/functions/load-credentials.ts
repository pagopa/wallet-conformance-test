import { SDJwt } from "@sd-jwt/core";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";

import { loadJwks, parseMdoc } from "@/logic";
import { Config, Credential, CredentialWithKey, Logger } from "@/types";

import { createMockSdJwt } from "./mock-credentials";

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
  try {
    if (!existsSync(path))
      mkdirSync(path, {
        recursive: true,
      });
  } catch (e) {
    const err = e as Error;
    throw new Error(
      `unable to find or create necessary directories ${path}: ${err.message}`,
    );
  }

  const files = readdirSync(path);
  const credentials: Record<string, Credential> = {};

  for (const file of files) {
    // Skip if the file is not a recognized credential type
    if (!file || (types.length !== 0 && !types.find((name) => name === file))) {
      onIgnoreError(
        `Local credential '${file}' is not included in credential types, it will be ignored.`,
      );
      continue;
    }

    // First, attempt to parse the credential as a SD-JWT
    try {
      const credential = readFileSync(`${path}/${file}`, "utf-8");
      const parsed = await SDJwt.extractJwt(credential);

      credentials[file] = {
        compact: credential,
        parsed,
        typ: "dc+sd-jwt",
      };
      continue; // Move to the next file
    } catch (e) {
      const err = e as Error;
      onIgnoreError(
        `Local credential '${file}' was not a valid sd-jwt credential: ${err.message}`,
      );
    }

    // If SD-JWT verification fails, attempt to parse it as an MDOC
    try {
      const credential = readFileSync(`${path}/${file}`, "utf-8");
      const parsed = parseMdoc(Buffer.from(credential, "base64url"));

      // If validation is successful, add it to the credentials record
      credentials[file] = {
        compact: credential,
        parsed,
        typ: "mso_mdoc",
      };
    } catch (e) {
      const err = e as Error;
      onIgnoreError(`${file} was not a valid mdoc credential: ${err.message}`);
    }
  }

  return credentials;
}

export async function loadCredentialsForPresentation(
  config: Config,
  trustAnchorBaseUrl: string,
  log: Logger,
): Promise<CredentialWithKey[]> {
  const credentials: CredentialWithKey[] = [];
  try {
    const storedCredentials = await loadCredentials(
      config.wallet.credentials_storage_path,
      [],
      log.debug,
    );

    for (const [key, cred] of Object.entries(storedCredentials)) {
      const credentialKeyPair = await loadJwks(
        config.wallet.backup_storage_path,
        `${key}_jwks`,
      );

      credentials.push({
        credential: cred.compact,
        dpopJwk: credentialKeyPair.privateKey,
        typ: cred.typ,
      });
    }

    if (credentials.length === 0) throw new Error();
  } catch {
    const personIdentificationData = await createMockSdJwt(
      {
        iss: "https://issuer.example.com",
        trustAnchorBaseUrl,
        trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
      },
      config.wallet.backup_storage_path,
      config.wallet.credentials_storage_path,
    );

    const credentialKeyPair = await loadJwks(
      config.wallet.backup_storage_path,
      `dc_sd_jwt_PersonIdentificationData_jwks`,
    );

    credentials.push({
      credential: personIdentificationData.compact,
      dpopJwk: credentialKeyPair.privateKey,
      typ: personIdentificationData.typ,
    });
  }

  return credentials;
}
