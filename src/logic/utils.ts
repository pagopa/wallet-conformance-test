import type { CallbackContext } from "@pagopa/io-wallet-oauth2";

import {
  createFetcher,
  Fetch,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import * as x509 from "@peculiar/x509";
import { BinaryLike, createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "path";

import { CertificateExpiredError } from "@/errors";
import { Config, FetchWithRetriesResponse, KeyPair } from "@/types";

import {
  createAndSaveCertificate,
  createAndSaveCertificateWithKey,
  createAndSaveKeys,
  createAndSaveKeysWithX5C,
  verifyJwt,
} from ".";

// Re-export config loading functions
export {
  type CliOptions,
  loadConfig,
  loadConfigWithHierarchy,
} from "./config-loader";

export const partialCallbacks: Pick<
  CallbackContext,
  "generateRandom" | "hash" | "verifyJwt"
> = {
  generateRandom: randomBytes,
  hash: (data: BinaryLike, alg: string) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};

export function fetchWithConfig(network: Config["network"]): Fetch {
  return (input, init) =>
    fetch(input, {
      signal: AbortSignal.timeout(network.timeout * 1000),
      ...init,
      headers: {
        "X-Spec-Version": "1.3",
        ...(network.user_agent ? { "User-Agent": network.user_agent } : {}),
        ...init?.headers,
      },
    });
}

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
      const response = await createFetcher(fetchWithConfig(network))(url, {
        method: "GET",
        ...init,
        headers: {
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

export function buildAttestationPath(
  wallet: Config["wallet"],
  externalTaUrl?: string,
): string {
  const base = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_version}/${wallet.wallet_id}`;
  const suffix = externalTaUrl
    ? `-${Buffer.from(externalTaUrl).toString("base64url").slice(0, 12)}`
    : "";
  return `${base}${suffix}`;
}

export function buildCertPath(pathPrefix: string): string {
  return `${pathPrefix}_cert`;
}

export function buildJwksPath(pathPrefix: string): string {
  return `${pathPrefix}_jwks`;
}

/**
 * Ensures a directory exists, creating it if necessary.
 *
 * @param dirPath The directory path to ensure.
 * @returns `true` if the directory was freshly created, `false` if it already existed.
 * @throws An error if the directory could not be created.
 */
export function ensureDir(dirPath: string): boolean {
  if (existsSync(dirPath)) return false;
  try {
    mkdirSync(dirPath, { recursive: true });
    return true;
  } catch (e) {
    throw new Error(
      `unable to find or create necessary directory ${dirPath}: ${(e as Error).message}`,
    );
  }
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
  const dirCreated = ensureDir(certPath);

  if (!dirCreated) {
    try {
      const certPem = readFileSync(`${certPath}/${filename}`, "utf-8");
      const certDerBase64 = certPem
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(/\s+/g, "")
        .trim();

      return certDerBase64;
    } catch {
      /* fall through to generate */
    }
  }

  return await createAndSaveCertificate(
    `${certPath}/${filename}`,
    keyPair,
    subject,
  );
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
  const dirCreated = ensureDir(jwksPath);

  if (!dirCreated) {
    try {
      const jwksData = readFileSync(`${jwksPath}/${filename}`, "utf-8");
      return JSON.parse(jwksData) as KeyPair;
    } catch {
      /* fall through to generate */
    }
  }

  return await createAndSaveKeys(`${jwksPath}/${filename}`);
}

/**
 * Loads or generates JWKS with a self-signed X.509 certificate, saving it to a file.
 * @param jwksPath The directory path where JWKS files are stored.
 * @param filename The name of the JWKS file to load or create.
 * @returns A promise that resolves to the loaded or generated KeyPair.
 */
export async function loadJwksWithX5C(
  jwksPath: string,
  filename: string,
  caCertPath: string,
  caSubject: string,
): Promise<KeyPair> {
  const jwksDirCreated = ensureDir(jwksPath);
  const caCertDirCreated = ensureDir(caCertPath);

  if (!jwksDirCreated && !caCertDirCreated) {
    try {
      const jwksData = readFileSync(`${jwksPath}/${filename}`, "utf-8");
      return JSON.parse(jwksData) as KeyPair;
    } catch {
      /* fall through to generate */
    }
  }

  return await createAndSaveKeysWithX5C(
    filename,
    jwksPath,
    caCertPath,
    caSubject,
  );
}

/**
 * Loads an existing cert/key pair from `dir` if one is present, otherwise
 * creates a new one via {@link createAndSaveCertificateWithKey}.
 *
 * File discovery: looks for `${baseName}.cert.pem` and `${baseName}.key.pem` in `dir`.
 * Falls through to creation if the directory is absent, those files are missing,
 * or either file cannot be read.
 *
 * @param dir Directory to search or write files into.
 * @param baseName Base filename (without extension) for the cert and key files.
 * @param subject The subject / CN — used only when creation is needed.
 * @param extraExtensions Additional X.509 extensions — used only when creation is needed.
 * @returns The cert PEM, key PEM, and absolute paths of the cert and key files.
 */
export async function loadOrCreateCertificateWithKey(
  dir: string,
  baseName: string,
  subject: string,
  extraExtensions: x509.Extension[] = [],
): Promise<{
  certPath: string;
  certPem: string;
  keyPath: string;
  keyPem: string;
}> {
  const dirCreated = ensureDir(dir);

  if (!dirCreated) {
    const certPath = path.resolve(path.join(dir, `${baseName}.cert.pem`));
    const keyPath = path.resolve(path.join(dir, `${baseName}.key.pem`));
    if (existsSync(certPath) && existsSync(keyPath)) {
      try {
        const certPem = readFileSync(certPath, "utf-8");
        const keyPem = readFileSync(keyPath, "utf-8");
        //TODO: Await WLEO-885 to replace with proper expiration check method
        const cert = new x509.X509Certificate(certPem);
        if (cert.notAfter < new Date()) {
          rmSync(certPath);
          rmSync(keyPath);
          //We throw an error to explicitly mark the fact that the flow is stopped,
          //falling through here makes the code far less understandable.
          throw new CertificateExpiredError("Stored certificate has expired");
        } else {
          return { certPath, certPem, keyPath, keyPem };
        }
      } catch {
        /* fall through to generate */
      }
    }
  }

  return createAndSaveCertificateWithKey(
    dir,
    baseName,
    subject,
    extraExtensions,
  );
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

/**
 * Validates that a given key pair has a `kid` and that the `kid` matches between the private and public keys.
 * @param keyPair The key pair to validate.
 * @throws An error if the key pair is invalid.
 */
export const validateProviderKeyPair = (keyPair: KeyPair): void => {
  if (!keyPair.privateKey.kid) {
    throw new Error("invalid key pair: kid missing");
  }
  if (keyPair.privateKey.kid !== keyPair.publicKey.kid) {
    throw new Error("invalid key pair: kid does not match");
  }
};
