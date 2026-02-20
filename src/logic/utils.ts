import type { CallbackContext } from "@pagopa/io-wallet-oauth2";

import { BinaryLike, createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "path";

import { Config, FetchWithRetriesResponse, KeyPair } from "@/types";

import { createAndSaveCertificate, createAndSaveKeys, verifyJwt } from ".";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";

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

/**
 * Fetches a resource with a specified number of retries on failure.
 *
 * @param url The URL of the resource to fetch.
 * @param network The network configuration, including timeout and max retries.
 * @param init Optional request initialization options.
 * @returns A promise that resolves to the fetch response and the number of attempts made.
 * @throws An error if the request times out or fails after all retries.
 */
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
  version: ItWalletSpecsVersion = ItWalletSpecsVersion.V1_0
) => {
  const dumpsDir = path.resolve(process.cwd(), "./dumps");

  const filePath = path.join(dumpsDir, version, fileName);
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

export function buildCertPath(pathPrefix: string): string {
  return `${pathPrefix}_cert`;
}

export function buildJwksPath(pathPrefix: string): string {
  return `${pathPrefix}_jwks`;
}

/**
 * Loads a certificate from a file, or creates and saves it if it doesn't exist.
 *
 * @param certPath The directory path where the certificate is stored.
 * @param filename The name of the certificate file.
 * @param keyPair The key pair to use if creating a new certificate.
 * @param subject The subject name to use if creating a new certificate.
 * @returns A promise that resolves to the certificate in PEM format.
 */
export async function loadCertificate(
  certPath: string,
  filename: string,
  keyPair: KeyPair,
  subject: string,
): Promise<string> {
  try {
    if (!existsSync(certPath))
      mkdirSync(certPath, {
        recursive: true,
      });
  } catch (e) {
    const err = e as Error;
    throw new Error(
      `unable to find or create necessary directories ${certPath}: ${err.message}`,
    );
  }

  try {
    const certPem = readFileSync(`${certPath}/${filename}`, "utf-8");
    const certDerBase64 = certPem
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\s+/g, "")
      .trim();

    return certDerBase64;
  } catch {
    return await createAndSaveCertificate(
      `${certPath}/${filename}`,
      keyPair,
      subject,
    );
  }
}

/**
 * Loads or generates JWKS saving it to a file.
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
    return await createAndSaveKeys(`${jwksPath}/${filename}`);
  }
}

export async function loadJwksWithSelfSignedX5c(
  trust: Config["trust"],
  namePrefix: string,
): Promise<KeyPair> {
  const signedJwks = await loadJwks(
    trust.federation_trust_anchors_jwks_path,
    buildJwksPath(namePrefix),
  );

  if (!signedJwks.publicKey.x5c || signedJwks.publicKey.x5c.length === 0)
    signedJwks.publicKey.x5c = [
      await loadCertificate(
        trust.ca_cert_path,
        buildCertPath(namePrefix),
        signedJwks,
        trust.certificate_subject,
      ),
    ];

  return signedJwks;
}

/**
 * Saves a credential to disk.
 * @param credentialsStoragePath The directory path where credentials are stored.
 * @param credentialConfigurationId The credential configuration identifier (used as filename).
 * @param credential The credential in compact format to save.
 * @returns The full path where the credential was saved, or null if saving failed.
 */
export function saveCredentialToDisk(
  credentialsStoragePath: string,
  credentialConfigurationId: string,
  credential: string,
  version: ItWalletSpecsVersion = ItWalletSpecsVersion.V1_0
): null | string {
  try {
    const credentialsPath = path.resolve(process.cwd(), credentialsStoragePath, version);

    // Ensure the directory exists
    if (!existsSync(credentialsPath)) {
      mkdirSync(credentialsPath, { recursive: true });
    }

    const filePath = `${credentialsPath}/${credentialConfigurationId}`;
    writeFileSync(filePath, credential);

    return filePath;
  } catch {
    return null;
  }
}

export const parseItWalletSpecVersion = (version : string) : version is ItWalletSpecsVersion => {
  return Object.values(ItWalletSpecsVersion).includes(version as ItWalletSpecsVersion)
}