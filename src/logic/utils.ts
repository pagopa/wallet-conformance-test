import type { CallbackContext } from "@pagopa/io-wallet-oauth2";

import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { BinaryLike, createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "path";

import { Config, FetchWithRetriesResponse, KeyPair } from "@/types";

import { createAndSaveCertificate, createAndSaveKeys, verifyJwt } from ".";

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
          ...(network.user_agent ? { "User-Agent": network.user_agent } : {}),
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
  version: ItWalletSpecsVersion,
) => {
  const dumpsDir = path.resolve(process.cwd(), "./dumps");

  const filePath = path.join(dumpsDir, version, fileName);
  if (!existsSync(filePath)) {
    throw new Error(`File ${filePath} not found`);
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
      `Missing file or invalid JSON in ${filePath}: ${(e as Error).message}`,
    );
  }
};

export function buildAttestationPath(wallet: Config["wallet"]): string {
  return `${wallet.wallet_attestations_storage_path}/${wallet.wallet_version}/${wallet.wallet_id}`;
}

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

/**
 * Loads a Trust Anchor (TA) JWKS with a self-signed X.509 certificate chain.
 *
 * If the JWKS public key does not contain an x5c (X.509 certificate chain),
 * this function loads a certificate from the configured CA certificate path
 * and populates it.
 *
 * @param trust - The trust configuration containing paths to federation trust anchors JWKS and CA certificates
 * @param namePrefix - The prefix used to build the path for loading JWKS and certificate files
 * @returns A promise that resolves to a KeyPair object containing the public key with an x5c certificate chain
 *
 * @throws Will throw an error if the JWKS or certificate file cannot be loaded
 *
 * @example
 * ```typescript
 * const keyPair = await loadTAJwksWithSelfSignedX5c(config.trust, 'ta-anchor');
 * ```
 */
export async function loadTAJwksWithSelfSignedX5c(
  trust: Omit<
    Config["trust"],
    "eidas_trusted_lists" | "federation_trust_anchors"
  >,
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
        trust.certificate_subject || "CN=localhost",
      ),
    ];

  return signedJwks;
}

/**
 * Loads (or lazily generates and caches on disk) an X.509 certificate for the
 * wallet provider key pair, suitable for use in
 * WalletAttestationOptionsV1_3.signer.x5c.
 *
 * Follows the same lazy-cache pattern as loadCertificate /
 * loadTAJwksWithSelfSignedX5c.
 *
 * @param wallet - The wallet configuration section from Config
 * @param providerKeyPair - The provider key pair loaded from backup_storage_path
 * @returns A non-empty tuple of base64-DER certificate strings: [leaf, ...chain]
 */
export async function loadWalletProviderCertificate(
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
): Promise<[string, ...string[]]> {
  const providerDomain = new URL(wallet.wallet_provider_base_url).hostname;
  const cert = await loadCertificate(
    wallet.backup_storage_path,
    "wallet_provider_cert",
    providerKeyPair,
    `CN=${providerDomain}`,
  );
  return [cert];
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
  version: ItWalletSpecsVersion,
): null | string {
  try {
    const credentialsPath = path.resolve(
      process.cwd(),
      credentialsStoragePath,
      version,
    );

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
