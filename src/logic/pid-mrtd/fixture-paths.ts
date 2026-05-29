import path from "node:path";

import { packageRoot } from "@/logic/runtime-paths";

/** Relative path from the package root to persisted PID MRTD PKI fixtures. */
export const PID_MRTD_FIXTURE_RELATIVE_DIR = "tests/fixtures/pid-mrtd";

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

/** Absolute path to the default PID MRTD fixture directory. */
export function defaultPidMrtdFixtureDir(): string {
  return path.join(packageRoot, PID_MRTD_FIXTURE_RELATIVE_DIR);
}

/** Resolves absolute paths for all persisted CSCA/DSC fixture files. */
export function resolvePidMrtdFixturePaths(
  fixtureDir = defaultPidMrtdFixtureDir(),
): PidMrtdFixturePaths {
  return {
    cscaCertPath: path.join(fixtureDir, CSCA_CERT_FILENAME),
    cscaKeyPath: path.join(fixtureDir, CSCA_KEY_FILENAME),
    dir: fixtureDir,
    dscCertPath: path.join(fixtureDir, DSC_CERT_FILENAME),
    dscKeyPath: path.join(fixtureDir, DSC_KEY_FILENAME),
  };
}
