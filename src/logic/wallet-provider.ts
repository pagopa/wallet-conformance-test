import * as x509 from "@peculiar/x509";
import { calculateJwkThumbprint, exportJWK } from "jose";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import type { Config, KeyPair } from "@/types";

import { createKeys } from "./jwk";
import {
  createSignedCertificate,
  hasWalletProviderCertificateIdentity,
  hasX509CertificateExpired,
  pemToBase64Der,
} from "./pem";
import { buildJwksPath, ensureDir, loadJwks } from "./utils";
import {
  getWalletProviderCertificateSubject,
  getWalletProviderHostname,
  resolveWalletProviderEntityIdentifier,
} from "./wallet-provider-url";

/** Filenames for persisted intermediate artefacts */
const CA_INTERMEDIATE_CERT = "ca_intermediate_cert";
const GENERATED_MATERIAL_METADATA = "wallet_provider_material_metadata.json";
const WALLET_PROVIDER_CERT = "wallet_provider_cert";

interface CachedCertificate {
  derBase64?: string;
  exists: boolean;
  label: string;
  path: string;
  pem?: string;
  validationError?: string;
}

interface GeneratedMaterialMetadata {
  caIntermediateCertSha256: string;
  generatedBy: "wallet-conformance-test";
  walletProviderCertSha256: string;
}

type WalletProviderMaterialMode =
  | "missing"
  | "tool-managed"
  | "user-provisioned";

/**
 * Loads (or lazily generates and caches on disk) the X.509 certificate chain
 * for the wallet provider key pair, suitable for use in the `x5c` header
 * of wallet attestations and key attestations.
 *
 * The chain follows the IT-Wallet specification:
 *
 *   TA  → signs → CA1  (intermediate, attests KY1)
 *   KY1 → signs → CA2  (leaf, attests providerKeyPair / KY2)
 *
 * Returned array: `[CA2, CA1]` (leaf → root, per x5c / RFC 7517 §4.7).
 *
 * Intermediate artefacts (KY1 key pair + CA1 cert) are persisted under
 * `trust.ca_cert_path`.  The leaf CA2 cert is persisted under
 * `wallet.backup_storage_path`.
 *
 * If either tool-managed certificate in the chain is expired the entire chain
 * is regenerated.
 *
 * Before reuse, the cached leaf signature is verified against the cached
 * intermediate and the leaf public key is checked against `providerKeyPair`.
 * Invalid user-provisioned chains cause this function to throw instead of
 * deleting externally managed material. Tool-managed material is derived from a
 * content hash metadata file written when this function generates the chain.
 *
 * @param wallet - The wallet configuration section from Config
 * @param trust - The trust configuration section (provides TA keys + CA cert path)
 * @param providerKeyPair - The provider key pair loaded from backup_storage_path (KY2)
 * @returns A non-empty tuple of base64-DER certificate strings: [CA2, CA1]
 */
export async function loadWalletProviderCertificate(
  wallet: Config["wallet"],
  trust: Config["trust"],
  providerKeyPair: KeyPair,
): Promise<[string, ...string[]]> {
  const caCertPath = trust.ca_cert_path;
  const backupPath = wallet.backup_storage_path;

  ensureDir(caCertPath);
  ensureDir(backupPath);

  const wpIntermediateCertPath = path.resolve(
    path.join(caCertPath, CA_INTERMEDIATE_CERT),
  );
  const wpCertPath = path.resolve(path.join(backupPath, WALLET_PROVIDER_CERT));
  const generatedMaterialMetadataPath = path.resolve(
    path.join(backupPath, GENERATED_MATERIAL_METADATA),
  );

  // ── Try loading the cached chain ──────────────────────────────────────
  const wpIntermediateCachedCert = loadCachedCert(
    wpIntermediateCertPath,
    "intermediate Wallet Provider certificate",
  );
  const wpCachedCert = loadCachedCert(
    wpCertPath,
    "Wallet Provider certificate",
  );
  const materialMode = deriveWalletProviderMaterialMode(
    generatedMaterialMetadataPath,
    wpCachedCert,
    wpIntermediateCachedCert,
    wallet,
  );

  const validationError = await validateCachedCertificateMaterial(
    wpCachedCert,
    wpIntermediateCachedCert,
    resolveWalletProviderEntityIdentifier(wallet),
    providerKeyPair,
  );
  if (!validationError) {
    if (!wpCachedCert.derBase64 || !wpIntermediateCachedCert.derBase64) {
      throw new Error(
        "Wallet Provider certificate material passed validation without loaded certificates",
      );
    }

    return [wpCachedCert.derBase64, wpIntermediateCachedCert.derBase64];
  }

  if (materialMode === "user-provisioned") {
    throw new Error(
      `User-provisioned Wallet Provider certificate material is invalid: ${validationError}. ` +
        `The files at "${wpCertPath}" and "${wpIntermediateCertPath}" were not deleted. ` +
        `Replace them with valid material or remove them to let the tool generate a new cache.`,
    );
  }

  // ── Invalidate stale artefacts ────────────────────────────────────────
  for (const p of [
    wpIntermediateCertPath,
    wpCertPath,
    generatedMaterialMetadataPath,
  ]) {
    if (existsSync(p)) rmSync(p);
  }

  // ── Load Trust Anchor key pair ────────────────────────────────────────
  const taKeyPair = await loadJwks(
    trust.federation_trust_anchors_jwks_path,
    buildJwksPath("trust_anchor"),
  );

  // ── Generate intermediate key pair (KY1) ──────────────────────────────
  const wpIntermediateKeyPair = await createKeys();

  // ── wpIntermediateCert: signed by TA, attests KY1 (isCA = true) ─────────────────────
  const taSubject = trust.certificate_subject;
  const wpEntityIdentifier = resolveWalletProviderEntityIdentifier(wallet);
  const wpSubject = getWalletProviderCertificateSubject(wpEntityIdentifier);

  const wpIntermediateCert = await createSignedCertificate(
    taKeyPair,
    taSubject,
    wpIntermediateKeyPair,
    wpSubject,
    true,
  );

  writeFileSync(wpIntermediateCertPath, wpIntermediateCert.toString("pem"));
  const wpIntermediateCertBase64 = Buffer.from(
    wpIntermediateCert.rawData,
  ).toString("base64");

  // ── CA2: signed by KY1, attests providerKeyPair / KY2 (leaf) ─────────
  const wpCert = await createSignedCertificate(
    wpIntermediateKeyPair,
    wpSubject,
    providerKeyPair,
    wpSubject,
    false,
    [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: "dns", value: getWalletProviderHostname(wpEntityIdentifier) },
          { type: "url", value: wpEntityIdentifier },
        ],
        false,
      ),
    ],
  );

  writeFileSync(wpCertPath, wpCert.toString("pem"));
  const wpCertBase64 = Buffer.from(wpCert.rawData).toString("base64");

  writeGeneratedMaterialMetadata(generatedMaterialMetadataPath, {
    caIntermediateCertSha256: sha256(wpIntermediateCert.toString("pem")),
    generatedBy: "wallet-conformance-test",
    walletProviderCertSha256: sha256(wpCert.toString("pem")),
  });

  return [wpCertBase64, wpIntermediateCertBase64];
}

function deriveWalletProviderMaterialMode(
  metadataPath: string,
  leafCert: CachedCertificate,
  intermediateCert: CachedCertificate,
  wallet: Config["wallet"],
): WalletProviderMaterialMode {
  const existingCerts = [leafCert, intermediateCert].filter(
    (cert) => cert.exists,
  );
  if (existingCerts.length === 0) {
    return "missing";
  }

  if (!wallet.wallet_provider_base_url) {
    return "tool-managed";
  }

  const metadata = loadGeneratedMaterialMetadata(metadataPath);
  if (!metadata) {
    return "user-provisioned";
  }

  const hashesByPath = new Map([
    [intermediateCert.path, metadata.caIntermediateCertSha256],
    [leafCert.path, metadata.walletProviderCertSha256],
  ]);
  const metadataMatchesExistingFiles = existingCerts.every(
    (cert) => cert.pem && sha256(cert.pem) === hashesByPath.get(cert.path),
  );

  return metadataMatchesExistingFiles ? "tool-managed" : "user-provisioned";
}

function isGeneratedMaterialMetadata(
  metadata: unknown,
): metadata is GeneratedMaterialMetadata {
  return (
    typeof metadata === "object" &&
    metadata !== null &&
    "generatedBy" in metadata &&
    metadata.generatedBy === "wallet-conformance-test" &&
    "walletProviderCertSha256" in metadata &&
    typeof metadata.walletProviderCertSha256 === "string" &&
    "caIntermediateCertSha256" in metadata &&
    typeof metadata.caIntermediateCertSha256 === "string"
  );
}

/**
 * Loads a persisted certificate from disk with enough detail to decide whether
 * invalid material may be regenerated or must be reported to the user.
 */
function loadCachedCert(filePath: string, label: string): CachedCertificate {
  if (!existsSync(filePath)) return { exists: false, label, path: filePath };

  let certPem: string;
  try {
    certPem = readFileSync(filePath, "utf-8");
  } catch (e) {
    const err = e as { code?: string };
    if (err.code === "ENOENT") return { exists: false, label, path: filePath };

    throw e;
  }

  try {
    const certDerBase64 = pemToBase64Der(certPem);
    if (hasX509CertificateExpired(certDerBase64)) {
      return {
        exists: true,
        label,
        path: filePath,
        pem: certPem,
        validationError: `${label} has expired`,
      };
    }

    return {
      derBase64: certDerBase64,
      exists: true,
      label,
      path: filePath,
      pem: certPem,
    };
  } catch (error) {
    return {
      exists: true,
      label,
      path: filePath,
      pem: certPem,
      validationError: `${label} is not a valid PEM certificate: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

function loadGeneratedMaterialMetadata(
  metadataPath: string,
): GeneratedMaterialMetadata | undefined {
  if (!existsSync(metadataPath)) {
    return undefined;
  }

  try {
    const metadata: unknown = JSON.parse(readFileSync(metadataPath, "utf-8"));
    return isGeneratedMaterialMetadata(metadata) ? metadata : undefined;
  } catch {
    return undefined;
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Verifies that a cached Wallet Provider certificate chain still belongs to
 * the current provider key pair before it is reused.
 */
async function validateCachedCertificateChain(
  leafCertDerBase64: string,
  intermediateCertDerBase64: string,
  providerKeyPair: KeyPair,
): Promise<void> {
  const leafCertificate = new x509.X509Certificate(
    Buffer.from(leafCertDerBase64, "base64"),
  );
  const intermediateCertificate = new x509.X509Certificate(
    Buffer.from(intermediateCertDerBase64, "base64"),
  );

  const leafSignatureValid = await leafCertificate.verify({
    publicKey: intermediateCertificate,
    signatureOnly: true,
  });
  if (!leafSignatureValid) {
    throw new Error(
      "Wallet Provider certificate chain leaf signature is invalid",
    );
  }

  const [cachedLeafJwk, providerJwkThumbprint] = await Promise.all([
    exportJWK(await leafCertificate.publicKey.export()),
    calculateJwkThumbprint(providerKeyPair.publicKey),
  ]);
  const cachedLeafThumbprint = await calculateJwkThumbprint(cachedLeafJwk);

  if (cachedLeafThumbprint !== providerJwkThumbprint) {
    throw new Error(
      "Wallet Provider certificate does not match the current provider key",
    );
  }
}

async function validateCachedCertificateMaterial(
  leafCert: CachedCertificate,
  intermediateCert: CachedCertificate,
  walletProviderBaseUrl: string,
  providerKeyPair: KeyPair,
): Promise<string | undefined> {
  if (!leafCert.exists && !intermediateCert.exists) {
    return "Wallet Provider certificate material is missing";
  }
  if (!leafCert.exists) {
    return `missing ${leafCert.label} at "${leafCert.path}"`;
  }
  if (!intermediateCert.exists) {
    return `missing ${intermediateCert.label} at "${intermediateCert.path}"`;
  }
  if (leafCert.validationError) {
    return leafCert.validationError;
  }
  if (intermediateCert.validationError) {
    return intermediateCert.validationError;
  }

  if (!leafCert.derBase64) {
    return `${leafCert.label} could not be loaded`;
  }
  if (!intermediateCert.derBase64) {
    return `${intermediateCert.label} could not be loaded`;
  }

  const leafDerBase64 = leafCert.derBase64;
  const intermediateDerBase64 = intermediateCert.derBase64;
  if (
    !hasWalletProviderCertificateIdentity(leafDerBase64, walletProviderBaseUrl)
  ) {
    return (
      `Wallet Provider certificate identity does not match ` +
      `wallet_provider_base_url "${walletProviderBaseUrl}"`
    );
  }

  try {
    await validateCachedCertificateChain(
      leafDerBase64,
      intermediateDerBase64,
      providerKeyPair,
    );
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }

  return undefined;
}

function writeGeneratedMaterialMetadata(
  metadataPath: string,
  metadata: GeneratedMaterialMetadata,
): void {
  writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
}
