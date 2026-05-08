import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";

import { CertificateExpiredError } from "@/errors";
import { LOCAL_WP_HOST } from "@/servers/wp-server";
import { Config, KeyPair } from "@/types";

import { createKeys } from "./jwk";
import {
  createSignedCertificate,
  hasAnyCertificateExpired,
  hasX509CertificateExpired,
} from "./pem";
import { ensureDir, loadJwks } from "./utils";

/** Filenames for persisted intermediate artefacts */
const CA_INTERMEDIATE_JWKS = "ca_intermediate_jwks";
const CA_INTERMEDIATE_CERT = "ca_intermediate_cert";
const WALLET_PROVIDER_CERT = "wallet_provider_cert";

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
 * If either certificate in the chain is expired the entire chain is
 * regenerated.
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

  const ca1Path = `${caCertPath}/${CA_INTERMEDIATE_CERT}`;
  const ca2Path = `${backupPath}/${WALLET_PROVIDER_CERT}`;

  // ── Try loading the cached chain ──────────────────────────────────────
  const cachedCA1 = loadCachedCert(ca1Path);
  const cachedCA2 = loadCachedCert(ca2Path);

  if (
    cachedCA1 &&
    cachedCA2 &&
    !hasAnyCertificateExpired([cachedCA2, cachedCA1])
  ) {
    return [cachedCA2, cachedCA1];
  }

  // ── Invalidate stale artefacts ────────────────────────────────────────
  for (const p of [ca1Path, ca2Path]) {
    if (existsSync(p)) rmSync(p);
  }

  // ── Load Trust Anchor key pair ────────────────────────────────────────
  const taKeyPair = await loadJwks(
    trust.federation_trust_anchors_jwks_path,
    "trust_anchor_jwks",
  );

  // ── Generate intermediate key pair (KY1) ──────────────────────────────
  const intermediateKeyPair = await createKeys();
  const intermediateJwksPath = `${caCertPath}/${CA_INTERMEDIATE_JWKS}`;

  if (existsSync(intermediateJwksPath)) rmSync(intermediateJwksPath);
  writeFileSync(intermediateJwksPath, JSON.stringify(intermediateKeyPair));

  // ── CA1: signed by TA, attests KY1 (isCA = true) ─────────────────────
  const taSubject = trust.certificate_subject;
  const intermediateSubject = "CN=WalletProvider Intermediate CA";

  const ca1Cert = await createSignedCertificate(
    taKeyPair,
    taSubject,
    intermediateKeyPair,
    intermediateSubject,
    true,
  );

  writeFileSync(ca1Path, ca1Cert.toString("pem"));
  const ca1Base64 = Buffer.from(ca1Cert.rawData).toString("base64");

  // ── CA2: signed by KY1, attests providerKeyPair / KY2 (leaf) ─────────
  const providerDomain = LOCAL_WP_HOST;

  const ca2Cert = await createSignedCertificate(
    intermediateKeyPair,
    intermediateSubject,
    providerKeyPair,
    `CN=${providerDomain}`,
    false,
  );

  writeFileSync(ca2Path, ca2Cert.toString("pem"));
  const ca2Base64 = Buffer.from(ca2Cert.rawData).toString("base64");

  return [ca2Base64, ca1Base64];
}

/**
 * Loads a persisted base64-DER certificate from disk.
 * Returns `undefined` if the file does not exist or is expired.
 */
function loadCachedCert(filePath: string): string | undefined {
  if (!existsSync(filePath)) return undefined;

  try {
    const certPem = readFileSync(filePath, "utf-8");
    const certDerBase64 = pemToBase64Der(certPem);

    if (hasX509CertificateExpired(certDerBase64)) {
      throw new CertificateExpiredError(
        "Certificate has expired and has to be regenerated",
      );
    }

    return certDerBase64;
  } catch {
    return undefined;
  }
}

/**
 * Strips PEM headers/footers and whitespace, returning the raw base64-DER
 * string suitable for an x5c array entry.
 */
function pemToBase64Der(pem: string): string {
  return pem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "")
    .trim();
}
