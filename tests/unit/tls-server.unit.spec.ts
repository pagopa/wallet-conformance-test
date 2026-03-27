import { addSecondsToDate } from "@pagopa/io-wallet-utils";
import * as x509 from "@peculiar/x509";
import { existsSync, rmSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";

import { loadOrCreateCertificateWithKey } from "@/logic";

const backupDir = "./tests/mocked-data/backup";
const certName = "server";

describe("Load server certificate test", async () => {
  afterEach(async () => {
    vi.useRealTimers();
    rmSync(`${backupDir}/${certName}.cert.pem`, { force: true });
    rmSync(`${backupDir}/${certName}.key.pem`, { force: true });
  });

  it("should generate a new certificate and key pair", async () => {
    const { certPath, certPem, keyPath } = await loadOrCreateCertificateWithKey(
      backupDir,
      certName,
      "CN=test_subject",
    );

    expect(
      existsSync(certPath),
      "The certificate file should've been created",
    ).toBe(true);
    expect(existsSync(keyPath), "The key file should've been created").toBe(
      true,
    );

    const decoded = new x509.X509Certificate(certPem);
    expect(
      decoded.subject,
      "certificate subject should match the passed subject",
    ).toBe("CN=test_subject");
  });

  it("should regenerate the certificate once it's expired", async () => {
    const now = new Date(2015, 1, 1);
    const twoYearsLater = addSecondsToDate(now, 3600 * 24 * 365 * 2);
    vi.useFakeTimers();

    vi.setSystemTime(now);

    const { certPem, keyPem } = await loadOrCreateCertificateWithKey(
      backupDir,
      certName,
      "CN=test_subject",
    );

    vi.setSystemTime(twoYearsLater);

    const { certPem: newCertPem, keyPem: newKeyPem } =
      await loadOrCreateCertificateWithKey(
        backupDir,
        certName,
        "CN=test_subject",
      );

    expect(certPem, "The certificate should've been regenerated").not.toEqual(
      newCertPem,
    );
    expect(keyPem, "The key should've been regenerated").not.toEqual(newKeyPem);

    vi.useRealTimers();
  });

  it("should include custom extensions in the generated certificate", async () => {
    // 1.2.840.113556.1.4.1 is a well-known custom OID (Microsoft AD objectGUID)
    // used here purely as a recognisable custom OID to verify round-trip behaviour.
    const CUSTOM_OID = "1.2.840.113556.1.4.1";
    const customExtension = new x509.Extension(
      CUSTOM_OID,
      false,
      new Uint8Array([0x05, 0x00]).buffer, // DER NULL value
    );

    const { certPem } = await loadOrCreateCertificateWithKey(
      backupDir,
      certName,
      "CN=test_subject",
      [customExtension],
    );

    const decoded = new x509.X509Certificate(certPem);
    const found = decoded.getExtension(CUSTOM_OID);

    expect(
      found,
      "custom extension should be present in the decoded certificate",
    ).not.toBeNull();
  });
});
