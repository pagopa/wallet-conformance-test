import * as x509 from "@peculiar/x509";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  generatePidMrtdFixtures,
  MOCK_CSCA_SUBJECT,
  MOCK_DSC_SUBJECT,
} from "@/logic/pid-mrtd/generate-fixtures";
import { verifyCscaDscChain } from "@/logic/pid-mrtd/verify-csca-dsc-chain";

/** @peculiar/x509 may insert spaces after RDN commas; compare canonically. */
function normalizeDn(dn: string): string {
  return dn.replace(/\s+/g, "").toUpperCase();
}

describe("PID MRTD PKI fixtures (REQ-02)", () => {
  let tempDir: string;

  afterEach(() => {
    if (tempDir) {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });

  it("generates CSCA and DSC PEM/key files", async () => {
    tempDir = mkdtempSync(path.join(tmpdir(), "wct-pid-mrtd-"));
    const paths = await generatePidMrtdFixtures(tempDir, { force: true });

    const csca = new x509.X509Certificate(
      readFileSync(paths.cscaCertPath, "utf-8"),
    );
    const dsc = new x509.X509Certificate(
      readFileSync(paths.dscCertPath, "utf-8"),
    );

    expect(normalizeDn(csca.subject), "CSCA subject").toBe(
      normalizeDn(MOCK_CSCA_SUBJECT),
    );
    expect(normalizeDn(dsc.subject), "DSC subject").toBe(
      normalizeDn(MOCK_DSC_SUBJECT),
    );
    expect(normalizeDn(dsc.issuer), "DSC issuer is CSCA").toBe(
      normalizeDn(MOCK_CSCA_SUBJECT),
    );

    const cscaBasicConstraints = csca.getExtension(
      x509.BasicConstraintsExtension,
    );
    expect(cscaBasicConstraints?.ca, "CSCA is a CA").toBe(true);

    const dscBasicConstraints = dsc.getExtension(
      x509.BasicConstraintsExtension,
    );
    expect(dscBasicConstraints?.ca, "DSC is not a CA").toBe(false);
  });

  it("skips regeneration when valid fixtures already exist", async () => {
    tempDir = mkdtempSync(path.join(tmpdir(), "wct-pid-mrtd-"));
    const first = await generatePidMrtdFixtures(tempDir, { force: true });
    const firstCsca = readFileSync(first.cscaCertPath, "utf-8");

    const second = await generatePidMrtdFixtures(tempDir);
    const secondCsca = readFileSync(second.cscaCertPath, "utf-8");

    expect(secondCsca, "fixture bytes unchanged on second run").toBe(firstCsca);
  });

  it("verifies CSCA → DSC chain with @peculiar/x509", async () => {
    tempDir = mkdtempSync(path.join(tmpdir(), "wct-pid-mrtd-"));
    const paths = await generatePidMrtdFixtures(tempDir, { force: true });

    const valid = await verifyCscaDscChain(paths);
    expect(valid, "@peculiar/x509 anchor + chain constraints").toBe(true);
  });

  it("rejects chain when DSC is used as the trust anchor", async () => {
    tempDir = mkdtempSync(path.join(tmpdir(), "wct-pid-mrtd-"));
    const paths = await generatePidMrtdFixtures(tempDir, { force: true });

    const valid = await verifyCscaDscChain({
      cscaCertPath: paths.dscCertPath,
      dscCertPath: paths.dscCertPath,
    });
    expect(valid, "non-CA cert must not pass as CSCA anchor").toBe(false);
  });
});
