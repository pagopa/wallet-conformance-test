/**
 * Bootstrap script for PID MRTD PKI fixtures (REQ-02 / FR-16).
 *
 * Usage:
 *   pnpm fixtures:pid-mrtd
 *   pnpm fixtures:pid-mrtd -- --force
 */
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { generatePidMrtdFixtures } from "@/logic/pid-mrtd/generate-fixtures";
import { resolvePidMrtdFixtureDir } from "@/logic/pid-mrtd/fixture-paths";

const force = process.argv.includes("--force");

let fixtureDir: string;
try {
  fixtureDir = resolvePidMrtdFixtureDir(loadConfigWithHierarchy());
} catch {
  fixtureDir = resolvePidMrtdFixtureDir();
}

const paths = await generatePidMrtdFixtures(fixtureDir, { force });

console.info(`PID MRTD fixtures ready in ${paths.dir}`);
console.info(`  CSCA: ${paths.cscaCertPath}`);
console.info(`  DSC:  ${paths.dscCertPath}`);
