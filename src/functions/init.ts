import { existsSync, rmSync } from "node:fs";
import path from "node:path";

import {
  buildCertPath,
  buildJwksPath,
  loadCertificate,
  loadJwks,
  loadJwksWithX5C,
  loadOrCreateServerCertificate,
  loadWalletProviderCertificate,
} from "@/logic";
import { Config } from "@/types";

export interface InitOptions {
  config: Config;
  force?: boolean;
  logger?: (message: string) => void;
}

/**
 * Pre-generates all cryptographic artifacts required for the conformance tests.
 * This command is idempotent by default, unless the 'force' option is used.
 *
 * @param options Initialization options including configuration and force flag.
 */
export async function runInit(options: InitOptions) {
  const { config, force, logger = console.log } = options;
  const { issuance, trust, trust_anchor, wallet } = config;

  logger("Initializing cryptographic artifacts...");

  const report: {
    file: string;
    status: "created" | "exists" | "overwritten";
  }[] = [];

  const trackFile = (filePath: string, existed: boolean) => {
    report.push({
      file: filePath,
      status: force && existed ? "overwritten" : existed ? "exists" : "created",
    });
  };

  const ensureFileRemoved = (dir: string, fileName: string) => {
    const filePath = path.join(dir, fileName);
    const existed = existsSync(filePath);
    if (force && existed) {
      rmSync(filePath, { force: true });
    }
    return existed;
  };

  // 1. Trust Anchor JWKS + CA certificate
  const taJwksName = "trust_anchor";
  const taExisted = ensureFileRemoved(
    trust.federation_trust_anchors_jwks_path,
    taJwksName,
  );
  ensureFileRemoved(trust.ca_cert_path, buildCertPath(taJwksName));

  await loadJwksWithX5C(
    trust.federation_trust_anchors_jwks_path,
    taJwksName,
    trust.ca_cert_path,
    trust.certificate_subject,
  );
  trackFile(
    path.join(trust.federation_trust_anchors_jwks_path, taJwksName),
    taExisted,
  );
  trackFile(
    path.join(trust.ca_cert_path, buildCertPath(taJwksName)),
    existsSync(path.join(trust.ca_cert_path, buildCertPath(taJwksName))),
  );

  // 2. Wallet Provider JWKS + Certificate Chain
  const wpJwksName = buildJwksPath("wallet_provider");
  const wpExisted = ensureFileRemoved(wallet.backup_storage_path, wpJwksName);
  const providerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    wpJwksName,
  );
  trackFile(path.join(wallet.backup_storage_path, wpJwksName), wpExisted);

  const wpCertName = "wallet_provider_cert";
  const wpCertExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    wpCertName,
  );
  // Ensure intermediate CA artifacts are also refreshed if forced
  ensureFileRemoved(trust.ca_cert_path, "ca_intermediate_cert");
  ensureFileRemoved(trust.ca_cert_path, "ca_intermediate_jwks");

  await loadWalletProviderCertificate(wallet, trust, providerKeyPair);
  trackFile(path.join(wallet.backup_storage_path, wpCertName), wpCertExisted);

  // 3. Wallet Unit JWKS + Self-Issued Certificate
  const unitJwksName = buildJwksPath("wallet_unit");
  const unitExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    unitJwksName,
  );
  const unitKeyPair = await loadJwks(wallet.backup_storage_path, unitJwksName);
  trackFile(path.join(wallet.backup_storage_path, unitJwksName), unitExisted);

  const unitCertName = "wallet_unit_self_issued_cert";
  const unitCertExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    unitCertName,
  );
  await loadCertificate(
    wallet.backup_storage_path,
    unitCertName,
    unitKeyPair,
    "CN=Wallet Unit",
  );
  trackFile(
    path.join(wallet.backup_storage_path, unitCertName),
    unitCertExisted,
  );

  // 4. Mocked Issuer artifacts (PID & mDL)
  // PID Issuer
  const pidIssuerJwksName = "issuer_pid_mocked_jwks";
  const pidIssuerExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    pidIssuerJwksName,
  );
  const pidIssuerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    pidIssuerJwksName,
  );
  trackFile(
    path.join(wallet.backup_storage_path, pidIssuerJwksName),
    pidIssuerExisted,
  );

  const pidCertName = "issuer_cert";
  const pidCertExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    pidCertName,
  );
  await loadCertificate(
    wallet.backup_storage_path,
    pidCertName,
    pidIssuerKeyPair,
    "CN=test_issuer",
  );
  trackFile(path.join(wallet.backup_storage_path, pidCertName), pidCertExisted);

  // PID Holder Key
  const pidHolderJwksName = buildJwksPath("dc_sd_jwt_PersonIdentificationData");
  const pidHolderExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    pidHolderJwksName,
  );
  await loadJwks(wallet.backup_storage_path, pidHolderJwksName);
  trackFile(
    path.join(wallet.backup_storage_path, pidHolderJwksName),
    pidHolderExisted,
  );

  // mDL Issuer
  const mdlIssuerJwksName = "issuer_mdl_mocked_jwks";
  const mdlIssuerExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    mdlIssuerJwksName,
  );
  const mdlIssuerKeyPair = await loadJwks(
    wallet.backup_storage_path,
    mdlIssuerJwksName,
  );
  trackFile(
    path.join(wallet.backup_storage_path, mdlIssuerJwksName),
    mdlIssuerExisted,
  );

  const mdlCertName = buildCertPath("mso_mdoc_mDL");
  const mdlCertExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    mdlCertName,
  );
  await loadCertificate(
    wallet.backup_storage_path,
    mdlCertName,
    mdlIssuerKeyPair,
    issuance.certificate_subject ?? trust.certificate_subject,
  );
  trackFile(path.join(wallet.backup_storage_path, mdlCertName), mdlCertExisted);

  // mDL Device Key
  const mdlDeviceJwksName = buildJwksPath("mso_mdoc_mDL");
  const mdlDeviceExisted = ensureFileRemoved(
    wallet.backup_storage_path,
    mdlDeviceJwksName,
  );
  await loadJwks(wallet.backup_storage_path, mdlDeviceJwksName);
  trackFile(
    path.join(wallet.backup_storage_path, mdlDeviceJwksName),
    mdlDeviceExisted,
  );

  // 5. TLS server certificate (for TA, WP, and CI servers)
  const tlsCertDir = trust_anchor.tls_cert_dir ?? "./data/backup";
  const tlsCertExisted = ensureFileRemoved(tlsCertDir, "server.cert.pem");
  ensureFileRemoved(tlsCertDir, "server.key.pem");
  await loadOrCreateServerCertificate(config);
  trackFile(path.join(tlsCertDir, "server.cert.pem"), tlsCertExisted);
  trackFile(path.join(tlsCertDir, "server.key.pem"), tlsCertExisted);

  logger("\nInitialization Report:");
  logger("-----------------------");
  for (const item of report) {
    logger(`${item.status.padEnd(12)}: ${item.file}`);
  }
  logger("-----------------------");
  logger("Initialization complete.");
}
