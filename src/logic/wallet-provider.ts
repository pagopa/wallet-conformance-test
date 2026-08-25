import * as x509 from "@peculiar/x509";
import { calculateJwkThumbprint, exportJWK } from "jose";
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
  resolveWalletProviderBaseUrl,
} from "./wallet-provider-url";

/** Filenames for persisted intermediate artefacts */
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
 * Before reuse, the cached leaf signature is verified against the cached
 * intermediate and the leaf public key is checked against `providerKeyPair`.
 * Invalid cached chains cause this function to throw instead of returning
 * unusable credentials.
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

  // ── Try loading the cached chain ──────────────────────────────────────
  const wpIntermediateCachedCert = loadCachedCert(wpIntermediateCertPath);
  const wpCachedCert = loadCachedCert(wpCertPath);

  if (
    wpCachedCert &&
    hasWalletProviderCertificateIdentity(
      wpCachedCert,
      resolveWalletProviderBaseUrl(wallet),
    ) &&
    wpIntermediateCachedCert
  ) {
    await validateCachedCertificateChain(
      wpCachedCert,
      wpIntermediateCachedCert,
      providerKeyPair,
    );
    return [wpCachedCert, wpIntermediateCachedCert];
  }

  // ── Invalidate stale artefacts ────────────────────────────────────────
  for (const p of [wpIntermediateCertPath, wpCertPath]) {
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
  const wpBaseUrl = resolveWalletProviderBaseUrl(wallet);
  const wpSubject = getWalletProviderCertificateSubject(wpBaseUrl);

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
          { type: "dns", value: getWalletProviderHostname(wpBaseUrl) },
          { type: "url", value: wpBaseUrl },
        ],
        false,
      ),
    ],
  );

  writeFileSync(wpCertPath, wpCert.toString("pem"));
  const wpCertBase64 = Buffer.from(wpCert.rawData).toString("base64");

  return [wpCertBase64, wpIntermediateCertBase64];
}

/**
 * Loads a persisted base64-DER certificate from disk.
 * Returns `undefined` if the file does not exist or is expired.
 */
function loadCachedCert(filePath: string): string | undefined {
  if (!existsSync(filePath)) return undefined;

  let certPem: string;
  try {
    certPem = readFileSync(filePath, "utf-8");
  } catch (e) {
    const err = e as { code?: string };
    if (err.code === "ENOENT") return undefined;

    throw e;
  }

  const certDerBase64 = pemToBase64Der(certPem);
  if (hasX509CertificateExpired(certDerBase64)) return undefined;

  return certDerBase64;
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
      "Cached Wallet Provider certificate chain leaf signature is invalid",
    );
  }

  const [cachedLeafJwk, providerJwkThumbprint] = await Promise.all([
    exportJWK(await leafCertificate.publicKey.export()),
    calculateJwkThumbprint(providerKeyPair.publicKey),
  ]);
  const cachedLeafThumbprint = await calculateJwkThumbprint(cachedLeafJwk);

  if (cachedLeafThumbprint !== providerJwkThumbprint) {
    throw new Error(
      "Cached Wallet Provider certificate does not match the current provider key",
    );
  }
}
