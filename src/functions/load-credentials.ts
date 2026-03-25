import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { SDJwt } from "@sd-jwt/core";
import { digest } from "@sd-jwt/crypto-nodejs";
import { decode } from "cbor";
import { readdirSync, readFileSync } from "node:fs";

import { buildJwksPath, ensureDir, loadJwks, parseMdoc } from "@/logic";
import { getLocalCiBaseUrl } from "@/servers/ci-server";
import {
  Config,
  Credential,
  CredentialWithKey,
  Logger,
  StatusClaim,
} from "@/types";

import {
  createMockMdlMdoc,
  createMockSdJwt,
  isCredentialMdocExpired,
  isCredentialSdJwtExpired,
} from "./mock-credentials";

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
  version: ItWalletSpecsVersion,
): Promise<Record<string, Credential>> {
  const pathVersion = `${path}/${version}`;
  ensureDir(pathVersion);

  const credentials: Record<string, Credential> = {};

  for (const file of readdirSync(pathVersion)) {
    if (types.length > 0 && !types.includes(file)) {
      onIgnoreError(
        `Local credential '${file}' is not included in credential types, it will be ignored.`,
      );
      continue;
    }

    const credential = await parseCredentialFile(
      `${pathVersion}/${file}`,
      file,
      onIgnoreError,
    );
    if (credential) {
      credentials[file] = credential;
    }
  }

  return credentials;
}

/**
 * Loads credentials for use in a presentation flow.
 * If credentials are found in the configured storage path they are returned with their key pairs;
 * otherwise mock credentials (PID + mDL) are generated and returned.
 *
 * @param config - The application configuration.
 * @param log - Logger instance used to surface ignored-credential warnings.
 * @returns An array of `CredentialWithKey` ready for the presentation orchestrator.
 */
export async function loadCredentialsForPresentation(
  config: Config,
  log: Logger,
): Promise<CredentialWithKey[]> {
  const storedCredentials = await loadCredentials(
    config.wallet.credentials_storage_path,
    [],
    log.debug,
    config.wallet.wallet_version,
  );

  if (Object.keys(storedCredentials).length === 0) {
    return createMockCredentialsWithKeys(config);
  }

  return Promise.all(
    Object.entries(storedCredentials).map(async ([key, credential]) => {
      const isExpired =
        credential.typ === "dc+sd-jwt"
          ? isCredentialSdJwtExpired(credential.parsed)
          : isCredentialMdocExpired(credential.parsed);
      if (isExpired) {
        const newCredential = await (credential.typ === "dc+sd-jwt"
          ? createMockSdJwt(
              {
                iss: getLocalCiBaseUrl(config.issuer.port),
                network: config.network,
                trust: config.trust,
                trustAnchor: config.trust_anchor,
              },
              config.wallet.backup_storage_path,
              config.wallet.credentials_storage_path,
              config.wallet.wallet_version,
            )
          : createMockMdlMdoc(
              config.issuance.certificate_subject ??
                `CN=${config.issuance.url}`,
              config.wallet.backup_storage_path,
              config.wallet.credentials_storage_path,
              config.wallet.wallet_version,
            ));

        return toCredentialWithKey(
          key,
          newCredential.compact,
          newCredential.typ,
          config.wallet.backup_storage_path,
        );
      } else {
        return toCredentialWithKey(
          key,
          credential.compact,
          credential.typ,
          config.wallet.backup_storage_path,
        );
      }
    }),
  );
}

export async function parseCredentialStatus(
  compact: string,
): Promise<null | StatusClaim> {
  const parsed = await parseCredential(compact);

  const { credential } = parsed;
  if (!credential)
    throw new Error(
      "unable to unmarshal string into sd-jwt or mdoc credential",
    );

  switch (credential.typ) {
    case "dc+sd-jwt":
      const sdJwtPayload = credential.parsed.payload;
      if (!sdJwtPayload) throw new Error("parsed sd-jwt has empty payload");

      return sdJwtPayload.status as StatusClaim;
    case "mso_mdoc":
      const mdocPayloadTag = decode(
        credential.parsed.issuerSigned.issuerAuth.payload,
      );
      const mdocPayload = decode(mdocPayloadTag.value);

      return mdocPayload.status as StatusClaim;
    default:
      return null;
  }
}

/**
 * Creates mock SD-JWT and MDOC credentials when no stored credentials are available.
 * Persists the generated credentials and their key pairs to the configured storage paths.
 *
 * @param config - The application configuration.
 * @returns A pair of mock `CredentialWithKey` entries: a PID (SD-JWT) and a mDL (MDOC).
 */
async function createMockCredentialsWithKeys(
  config: Config,
): Promise<CredentialWithKey[]> {
  const personIdentificationData = await createMockSdJwt(
    {
      iss: getLocalCiBaseUrl(config.issuer.port),
      network: config.network,
      trust: config.trust,
      trustAnchor: config.trust_anchor,
    },
    config.wallet.backup_storage_path,
    config.wallet.credentials_storage_path,
    config.wallet.wallet_version,
  );
  const mobileDriverLicence = await createMockMdlMdoc(
    config.issuance.certificate_subject ?? `CN=${config.issuance.url}`,
    config.wallet.backup_storage_path,
    config.wallet.credentials_storage_path,
    config.wallet.wallet_version,
  );

  return Promise.all([
    toCredentialWithKey(
      "dc_sd_jwt_PersonIdentificationData",
      personIdentificationData.compact,
      personIdentificationData.typ,
      config.wallet.backup_storage_path,
    ),
    toCredentialWithKey(
      "mso_mdoc_mDL",
      mobileDriverLicence.compact,
      mobileDriverLicence.typ,
      config.wallet.backup_storage_path,
    ),
  ]);
}
async function parseCredential(
  compact: string,
): Promise<{ credential?: Credential; error?: string }> {
  let error: null | string = null;

  try {
    const parsed = await SDJwt.decodeSDJwt(compact, digest);
    return { credential: { compact, parsed, typ: "dc+sd-jwt" } };
  } catch (e) {
    error = `Local credential was not a valid sd-jwt credential: ${e instanceof Error ? e.message : String(e)}`;
  }

  try {
    const parsed = parseMdoc(Buffer.from(compact, "base64url"));
    return { credential: { compact, parsed, typ: "mso_mdoc" }, error };
  } catch (e) {
    return {
      error: `Local credential was not a valid mdoc credential: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/**
 * Attempts to parse a credential file as SD-JWT first, then as MDOC.
 * Calls `onIgnoreError` for each failed attempt and returns `null` if both formats fail.
 *
 * @param filePath - Absolute path to the credential file.
 * @param fileName - File name used in error messages.
 * @param onIgnoreError - Callback invoked with a warning message when a parse attempt fails.
 * @returns The parsed `Credential`, or `null` if the file cannot be parsed in any supported format.
 */
async function parseCredentialFile(
  filePath: string,
  fileName: string,
  onIgnoreError: (msg: string) => void,
): Promise<Credential | null> {
  let compact: string;
  try {
    compact = readFileSync(filePath, "utf-8");
  } catch (e) {
    onIgnoreError(
      `Local credential '${fileName}' could not be read: ${e instanceof Error ? e.message : String(e)}`,
    );
    return null;
  }

  const parsed = await parseCredential(compact);
  if (parsed.error) onIgnoreError(`${fileName}: ${parsed.error}`);

  if (parsed.credential) return parsed.credential;

  return null;
}

/**
 * Loads the key pair for the given credential ID and assembles a `CredentialWithKey`.
 *
 * @param id - The credential identifier, used to locate the corresponding JWKS file.
 * @param compact - The compact-serialized credential string.
 * @param typ - The credential format type (`dc+sd-jwt` or `mso_mdoc`).
 * @param backupStoragePath - Directory where key pair files are stored.
 * @returns A `CredentialWithKey` combining the credential data with its private key.
 */
async function toCredentialWithKey(
  id: string,
  compact: string,
  typ: CredentialWithKey["typ"],
  backupStoragePath: string,
): Promise<CredentialWithKey> {
  const { privateKey } = await loadJwks(backupStoragePath, buildJwksPath(id));
  return { credential: compact, dpopJwk: privateKey, id, typ };
}
