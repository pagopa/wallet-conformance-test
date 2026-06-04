import path from "node:path";

import type { Config } from "@/types";

import { resolveWorkspacePath } from "@/logic/runtime-paths";

/** Subdirectory under {@link Config.wallet.backup_storage_path} for CSCA/DSC fixtures (B_1 FR-15). */
export const PID_MRTD_FIXTURE_DIRNAME = "pid-mrtd";

/**
 * Fallback when no config is loaded (e.g. `pnpm fixtures:pid-mrtd` without `config.ini`).
 * Matches `backup_storage_path = ./data/backup` + `/pid-mrtd` from `config.example.ini`.
 */
export const DEFAULT_PID_MRTD_FIXTURE_RELATIVE_PATH = "./data/backup/pid-mrtd";

export const CSCA_CERT_BASENAME = "csca";
export const DSC_CERT_BASENAME = "dsc";

export const CSCA_CERT_FILENAME = `${CSCA_CERT_BASENAME}.pem`;
export const CSCA_KEY_FILENAME = `${CSCA_CERT_BASENAME}.key`;
export const DSC_CERT_FILENAME = `${DSC_CERT_BASENAME}.pem`;
export const DSC_KEY_FILENAME = `${DSC_CERT_BASENAME}.key`;

export interface PidMrtdFixturePaths {
  cscaCertPath: string;
  cscaKeyPath: string;
  dir: string;
  dscCertPath: string;
  dscKeyPath: string;
}

/** @deprecated Prefer {@link resolvePidMrtdFixtureDir} with config when available. */
export function defaultPidMrtdFixtureDir(
  config?: Pick<Config, "issuance_pid" | "wallet">,
): string {
  return resolvePidMrtdFixtureDir(config);
}

/**
 * Resolves the directory for persisted PID MRTD PKI fixtures.
 *
 * Priority:
 * 1. `[issuance_pid].fixture_storage_path` when set in config
 * 2. `{wallet.backup_storage_path}/pid-mrtd` when config is available
 * 3. `./data/backup/pid-mrtd` relative to the current working directory
 */
export function resolvePidMrtdFixtureDir(
  config?: Pick<Config, "issuance_pid" | "wallet">,
): string {
  const explicit = config?.issuance_pid?.fixture_storage_path;
  if (explicit) {
    return explicit;
  }

  if (config?.wallet?.backup_storage_path) {
    return path.join(
      config.wallet.backup_storage_path,
      PID_MRTD_FIXTURE_DIRNAME,
    );
  }

  return resolveWorkspacePath(DEFAULT_PID_MRTD_FIXTURE_RELATIVE_PATH);
}

/** Resolves absolute paths for all persisted CSCA/DSC fixture files. */
export function resolvePidMrtdFixturePaths(
  fixtureDir = resolvePidMrtdFixtureDir(),
): PidMrtdFixturePaths {
  return {
    cscaCertPath: path.join(fixtureDir, CSCA_CERT_FILENAME),
    cscaKeyPath: path.join(fixtureDir, CSCA_KEY_FILENAME),
    dir: fixtureDir,
    dscCertPath: path.join(fixtureDir, DSC_CERT_FILENAME),
    dscKeyPath: path.join(fixtureDir, DSC_KEY_FILENAME),
  };
}
