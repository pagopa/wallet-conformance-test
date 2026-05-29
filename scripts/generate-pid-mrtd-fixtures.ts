/**
 * Bootstrap script for PID MRTD PKI fixtures (REQ-02 / FR-16).
 *
 * Usage:
 *   pnpm fixtures:pid-mrtd
 *   pnpm fixtures:pid-mrtd -- --force
 */
import { defaultPidMrtdFixtureDir } from "@/logic/pid-mrtd/fixture-paths";
import { generatePidMrtdFixtures } from "@/logic/pid-mrtd/generate-fixtures";

const force = process.argv.includes("--force");
const fixtureDir = defaultPidMrtdFixtureDir();

const paths = await generatePidMrtdFixtures(fixtureDir, { force });

console.info(`PID MRTD fixtures ready in ${paths.dir}`);
console.info(`  CSCA: ${paths.cscaCertPath}`);
console.info(`  DSC:  ${paths.dscCertPath}`);
