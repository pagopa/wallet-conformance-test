/* eslint-disable max-lines-per-function */
import * as x509 from "@peculiar/x509";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { Config, KeyPair } from "@/types";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { createKeys } from "@/logic/jwk";
import {
  createSignedCertificate,
  hasSanExtension,
  hasWalletProviderCertificateIdentity,
  OID_SUBJECT_ALTERNATIVE_NAME,
} from "@/logic/pem";
import { loadWalletProviderCertificate } from "@/logic/wallet-provider";
import { resolveWalletProviderBaseUrl } from "@/logic/wallet-provider-url";
import { LOCAL_WP_HOST } from "@/servers/wp-server";

afterEach(() => {
  vi.useRealTimers();
});

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
      "https://dev.eid.wallet.it/1-3/test-wallet-provider";
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
            { type: "dns", value: "dev.eid.wallet.it" },
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
        "https://dev.eid.wallet.it/1-3/test-wallet-provider",
      ),
    ).toBe(true);
  });

  it("rejects a cached certificate whose URI SAN belongs to another identifier", () => {
    expect(
      hasWalletProviderCertificateIdentity(
        certWithCustomIdentityDerBase64,
        "https://dev.eid.wallet.it/other-wallet-provider",
      ),
    ).toBe(false);
  });
});

describe("wallet_provider_cert cache validation", () => {
  const config = loadConfigWithHierarchy();

  async function createCachedCertificate(
    walletProviderBaseUrl:
      | null
      | string = "https://configured.example/wallet-provider",
  ) {
    const tempDir = mkdtempSync(path.join(tmpdir(), "wct-wallet-provider-"));
    const wallet = {
      ...config.wallet,
      backup_storage_path: path.join(tempDir, "backup"),
      wallet_provider_base_url: walletProviderBaseUrl ?? undefined,
    };
    const trust = {
      ...config.trust,
      ca_cert_path: path.join(tempDir, "ca"),
    };
    const providerKeyPair = await createKeys();
    const walletProviderCertPath = path.join(
      wallet.backup_storage_path,
      "wallet_provider_cert",
    );
    const intermediateCertPath = path.join(
      trust.ca_cert_path,
      "ca_intermediate_cert",
    );
    const metadataPath = path.join(
      wallet.backup_storage_path,
      "wallet_provider_material_metadata.json",
    );

    await loadWalletProviderCertificate(wallet, trust, providerKeyPair);

    return {
      intermediateCertPath,
      metadataPath,
      providerKeyPair,
      tempDir,
      trust,
      wallet,
      walletProviderCertPath,
    };
  }

  async function writeUserProvisionedCertificateMaterial(
    wallet: Config["wallet"],
    trust: Config["trust"],
    providerKeyPair: KeyPair,
    walletProviderBaseUrl: string,
  ) {
    mkdirSync(wallet.backup_storage_path, { recursive: true });
    mkdirSync(trust.ca_cert_path, { recursive: true });

    const intermediateKeyPair = await createKeys();
    const intermediateSubject = "CN=UserIntermediate";
    const intermediateCert = await createSignedCertificate(
      await createKeys(),
      "CN=UserTrustAnchor",
      intermediateKeyPair,
      intermediateSubject,
      true,
    );
    const leafCert = await createSignedCertificate(
      intermediateKeyPair,
      intermediateSubject,
      providerKeyPair,
      `CN=${new URL(walletProviderBaseUrl).hostname}`,
      false,
      [
        new x509.SubjectAlternativeNameExtension(
          [
            { type: "dns", value: new URL(walletProviderBaseUrl).hostname },
            { type: "url", value: walletProviderBaseUrl },
          ],
          false,
        ),
      ],
    );
    const walletProviderCertPath = path.join(
      wallet.backup_storage_path,
      "wallet_provider_cert",
    );
    const intermediateCertPath = path.join(
      trust.ca_cert_path,
      "ca_intermediate_cert",
    );

    writeFileSync(walletProviderCertPath, leafCert.toString("pem"));
    writeFileSync(intermediateCertPath, intermediateCert.toString("pem"));

    return { intermediateCertPath, walletProviderCertPath };
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

  it("fails fast and preserves user-provisioned material when the identity does not match", async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), "wct-wallet-provider-"));
    const wallet = {
      ...config.wallet,
      backup_storage_path: path.join(tempDir, "backup"),
      wallet_provider_base_url: "https://configured.example/wallet-provider",
    };
    const trust = {
      ...config.trust,
      ca_cert_path: path.join(tempDir, "ca"),
    };
    const providerKeyPair = await createKeys();

    try {
      const { intermediateCertPath, walletProviderCertPath } =
        await writeUserProvisionedCertificateMaterial(
          wallet,
          trust,
          providerKeyPair,
          "https://provisioned.example/wallet-provider",
        );
      const originalWalletProviderCert = readFileSync(
        walletProviderCertPath,
        "utf-8",
      );
      const originalIntermediateCert = readFileSync(
        intermediateCertPath,
        "utf-8",
      );

      await expect(
        loadWalletProviderCertificate(wallet, trust, providerKeyPair),
      ).rejects.toThrow(
        /User-provisioned Wallet Provider certificate material is invalid: Wallet Provider certificate identity does not match/,
      );

      expect(readFileSync(walletProviderCertPath, "utf-8")).toBe(
        originalWalletProviderCert,
      );
      expect(readFileSync(intermediateCertPath, "utf-8")).toBe(
        originalIntermediateCert,
      );
    } finally {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });

  it("fails fast and preserves user-provisioned material when the chain signature is invalid", async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), "wct-wallet-provider-"));
    const wallet = {
      ...config.wallet,
      backup_storage_path: path.join(tempDir, "backup"),
      wallet_provider_base_url: "https://provisioned.example/wallet-provider",
    };
    const trust = {
      ...config.trust,
      ca_cert_path: path.join(tempDir, "ca"),
    };
    const providerKeyPair = await createKeys();

    try {
      const { intermediateCertPath, walletProviderCertPath } =
        await writeUserProvisionedCertificateMaterial(
          wallet,
          trust,
          providerKeyPair,
          resolveWalletProviderBaseUrl(wallet),
        );
      const replacementIntermediate = await createSignedCertificate(
        await createKeys(),
        "CN=ReplacementIssuer",
        await createKeys(),
        "CN=ReplacementIntermediate",
        true,
      );
      writeFileSync(
        intermediateCertPath,
        replacementIntermediate.toString("pem"),
      );
      const originalWalletProviderCert = readFileSync(
        walletProviderCertPath,
        "utf-8",
      );
      const originalIntermediateCert = readFileSync(
        intermediateCertPath,
        "utf-8",
      );

      await expect(
        loadWalletProviderCertificate(wallet, trust, providerKeyPair),
      ).rejects.toThrow(
        /User-provisioned Wallet Provider certificate material is invalid: Wallet Provider certificate chain leaf signature is invalid/,
      );

      expect(readFileSync(walletProviderCertPath, "utf-8")).toBe(
        originalWalletProviderCert,
      );
      expect(readFileSync(intermediateCertPath, "utf-8")).toBe(
        originalIntermediateCert,
      );
    } finally {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });

  it("fails fast and preserves user-provisioned material when the certificate is expired", async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), "wct-wallet-provider-"));
    const wallet = {
      ...config.wallet,
      backup_storage_path: path.join(tempDir, "backup"),
      wallet_provider_base_url: "https://provisioned.example/wallet-provider",
    };
    const trust = {
      ...config.trust,
      ca_cert_path: path.join(tempDir, "ca"),
    };
    const providerKeyPair = await createKeys();

    try {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2020-01-01T00:00:00.000Z"));
      const { intermediateCertPath, walletProviderCertPath } =
        await writeUserProvisionedCertificateMaterial(
          wallet,
          trust,
          providerKeyPair,
          resolveWalletProviderBaseUrl(wallet),
        );
      const originalWalletProviderCert = readFileSync(
        walletProviderCertPath,
        "utf-8",
      );
      const originalIntermediateCert = readFileSync(
        intermediateCertPath,
        "utf-8",
      );

      vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));

      await expect(
        loadWalletProviderCertificate(wallet, trust, providerKeyPair),
      ).rejects.toThrow(
        /User-provisioned Wallet Provider certificate material is invalid: Wallet Provider certificate has expired/,
      );

      expect(readFileSync(walletProviderCertPath, "utf-8")).toBe(
        originalWalletProviderCert,
      );
      expect(readFileSync(intermediateCertPath, "utf-8")).toBe(
        originalIntermediateCert,
      );
    } finally {
      vi.useRealTimers();
      rmSync(tempDir, { force: true, recursive: true });
    }
  });

  it("regenerates tool-managed material when the configured identity changes", async () => {
    const {
      metadataPath,
      providerKeyPair,
      tempDir,
      trust,
      wallet,
      walletProviderCertPath,
    } = await createCachedCertificate();

    try {
      const originalWalletProviderCert = readFileSync(
        walletProviderCertPath,
        "utf-8",
      );
      const walletWithUpdatedIdentity = {
        ...wallet,
        wallet_provider_base_url:
          "https://dev.eid.wallet.it/updated-wallet-provider",
      };

      const regeneratedChain = await loadWalletProviderCertificate(
        walletWithUpdatedIdentity,
        trust,
        providerKeyPair,
      );

      expect(regeneratedChain).toHaveLength(2);
      expect(readFileSync(walletProviderCertPath, "utf-8")).not.toBe(
        originalWalletProviderCert,
      );
      expect(existsSync(metadataPath)).toBe(true);
      expect(
        hasWalletProviderCertificateIdentity(
          regeneratedChain[0],
          resolveWalletProviderBaseUrl(walletWithUpdatedIdentity),
        ),
      ).toBe(true);
    } finally {
      rmSync(tempDir, { force: true, recursive: true });
    }
  });
});
