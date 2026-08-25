import * as x509 from "@peculiar/x509";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { createKeys } from "@/logic/jwk";
import {
  createSignedCertificate,
  hasSanExtension,
  hasWalletProviderCertificateIdentity,
  OID_SUBJECT_ALTERNATIVE_NAME,
} from "@/logic/pem";
import { loadWalletProviderCertificate } from "@/logic/wallet-provider";
import { LOCAL_WP_HOST } from "@/servers/wp-server";

describe("wallet_provider_cert SAN", () => {
  let certWithSan: x509.X509Certificate;
  let certWithSanDerBase64: string;
  let certWithoutSanDerBase64: string;
  let certWithCustomIdentityDerBase64: string;

  beforeAll(async () => {
    const issuerKp = await createKeys();
    const subjectKp = await createKeys();
    certWithSan = await createSignedCertificate(
      issuerKp,
      "CN=TestIssuer",
      subjectKp,
      `CN=${LOCAL_WP_HOST}`,
      false,
      [
        new x509.SubjectAlternativeNameExtension(
          [{ type: "dns", value: LOCAL_WP_HOST }],
          false,
        ),
      ],
    );
    certWithSanDerBase64 = Buffer.from(certWithSan.rawData).toString("base64");

    const issuerKp2 = await createKeys();
    const subjectKp2 = await createKeys();
    const certWithoutSan = await createSignedCertificate(
      issuerKp2,
      "CN=TestIssuer",
      subjectKp2,
      `CN=${LOCAL_WP_HOST}`,
      false,
    );
    certWithoutSanDerBase64 = Buffer.from(certWithoutSan.rawData).toString(
      "base64",
    );

    const customProviderUrl =
      "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider";
    const customIssuerKp = await createKeys();
    const customSubjectKp = await createKeys();
    const customCert = await createSignedCertificate(
      customIssuerKp,
      "CN=TestIssuer",
      customSubjectKp,
      `C=IT, O=PagoPA S.p.A., CN=${customProviderUrl.slice("https://".length)}`,
      false,
      [
        new x509.SubjectAlternativeNameExtension(
          [
            { type: "dns", value: "dev.eid.wallet.ipzs.it" },
            { type: "url", value: customProviderUrl },
          ],
          false,
        ),
      ],
    );
    certWithCustomIdentityDerBase64 = Buffer.from(customCert.rawData).toString(
      "base64",
    );
  });

  it("leaf cert created with SAN extension carries OID 2.5.29.17", () => {
    expect(
      certWithSan.getExtension(OID_SUBJECT_ALTERNATIVE_NAME),
      "SAN extension must be present",
    ).not.toBeNull();
  });

  it("hasSanExtension returns true for cert with SAN", () => {
    expect(
      hasSanExtension(certWithSanDerBase64),
      "hasSanExtension should return true when SAN is present",
    ).toBe(true);
  });

  it("hasSanExtension returns false for cert without SAN", () => {
    expect(
      hasSanExtension(certWithoutSanDerBase64),
      "hasSanExtension should return false when SAN is absent",
    ).toBe(false);
  });

  it("hasSanExtension returns false for an empty string", () => {
    expect(
      hasSanExtension(""),
      "empty string should not throw and should return false",
    ).toBe(false);
  });

  it("hasSanExtension returns false for malformed base64 input", () => {
    expect(
      hasSanExtension("not-valid-der-base64!!!"),
      "malformed input should not throw and should return false",
    ).toBe(false);
  });

  it("accepts a certificate with a full subject whose SANs match the configured identifier", () => {
    expect(
      hasWalletProviderCertificateIdentity(
        certWithCustomIdentityDerBase64,
        "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider",
      ),
    ).toBe(true);
  });

  it("rejects a cached certificate whose URI SAN belongs to another identifier", () => {
    expect(
      hasWalletProviderCertificateIdentity(
        certWithCustomIdentityDerBase64,
        "https://dev.eid.wallet.ipzs.it/other-wallet-provider",
      ),
    ).toBe(false);
  });
});

describe("wallet_provider_cert cache validation", () => {
  const config = loadConfigWithHierarchy();

  async function createCachedCertificate() {
    const tempDir = mkdtempSync(path.join(tmpdir(), "wct-wallet-provider-"));
    const wallet = {
      ...config.wallet,
      backup_storage_path: path.join(tempDir, "backup"),
    };
    const trust = {
      ...config.trust,
      ca_cert_path: path.join(tempDir, "ca"),
    };
    const providerKeyPair = await createKeys();

    await loadWalletProviderCertificate(wallet, trust, providerKeyPair);

    return { providerKeyPair, tempDir, trust, wallet };
  }

  it("reuses a cached chain when its signature and provider key are valid", async () => {
    const { providerKeyPair, tempDir, trust, wallet } =
      await createCachedCertificate();

    try {
      const cachedChain = await loadWalletProviderCertificate(
        wallet,
        trust,
        providerKeyPair,
      );
      const reusedChain = await loadWalletProviderCertificate(
        wallet,
        trust,
        providerKeyPair,
      );

      expect(reusedChain).toEqual(cachedChain);
    } finally {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });

  it("rejects a cached leaf whose signature does not match the intermediate", async () => {
    const { providerKeyPair, tempDir, trust, wallet } =
      await createCachedCertificate();

    try {
      const replacementIntermediate = await createSignedCertificate(
        await createKeys(),
        "CN=ReplacementIssuer",
        await createKeys(),
        "CN=ReplacementIntermediate",
        true,
      );
      writeFileSync(
        path.join(tempDir, "ca", "ca_intermediate_cert"),
        replacementIntermediate.toString("pem"),
      );

      await expect(
        loadWalletProviderCertificate(wallet, trust, providerKeyPair),
      ).rejects.toThrow(
        "Cached Wallet Provider certificate chain leaf signature is invalid",
      );
    } finally {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });

  it("rejects a cached leaf that belongs to a previous provider key", async () => {
    const { tempDir, trust, wallet } = await createCachedCertificate();

    try {
      await expect(
        loadWalletProviderCertificate(wallet, trust, await createKeys()),
      ).rejects.toThrow(
        "Cached Wallet Provider certificate does not match the current provider key",
      );
    } finally {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });
});
