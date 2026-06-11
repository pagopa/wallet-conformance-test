/* eslint-disable max-lines-per-function */
import { existsSync, rmSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Config } from "@/types";

import { runInit } from "@/functions/init";

vi.mock("node:fs", async (importActual) => {
  const actual = await importActual<typeof import("node:fs")>();
  return {
    ...actual,
    existsSync: vi.fn(),
    rmSync: vi.fn(),
  };
});

vi.mock("@/logic", async (importActual) => {
  const actual = await importActual<typeof import("@/logic")>();
  return {
    ...actual,
    loadCertificate: vi.fn().mockResolvedValue("mock-cert-base64"),
    loadJwks: vi.fn().mockResolvedValue({
      privateKey: { alg: "ES256", kid: "test-kid" },
      publicKey: { alg: "ES256", kid: "test-kid" },
    }),
    loadJwksWithX5C: vi.fn().mockResolvedValue({
      privateKey: { alg: "ES256", kid: "test-kid" },
      publicKey: { alg: "ES256", kid: "test-kid", x5c: ["mock-cert"] },
    }),
    loadOrCreateServerCertificate: vi.fn().mockResolvedValue({
      certPath: "./test-tls/server.cert.pem",
      certPem: "mock-cert-pem",
      keyPath: "./test-tls/server.key.pem",
      keyPem: "mock-key-pem",
    }),
    loadWalletProviderCertificate: vi
      .fn()
      .mockResolvedValue(["mock-ca2-base64", "mock-ca1-base64"]),
  };
});

const mockExistsSync = vi.mocked(existsSync);
const mockRmSync = vi.mocked(rmSync);

const {
  buildCertPath,
  buildJwksPath,
  loadCertificate,
  loadJwks,
  loadJwksWithX5C,
  loadOrCreateServerCertificate,
  loadWalletProviderCertificate,
} = await import("@/logic");

const mockConfig = {
  issuance: { certificate_subject: undefined },
  trust: {
    ca_cert_path: "./test-certs",
    certificate_subject: "CN=test_trust_anchor",
    federation_trust_anchors_jwks_path: "./test-jwks",
  },
  trust_anchor: { tls_cert_dir: "./test-tls" },
  wallet: { backup_storage_path: "./test-backup" },
} as unknown as Config;

describe("runInit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("first run (no existing files)", () => {
    beforeEach(() => {
      mockExistsSync.mockReturnValue(false);
    });

    it("calls all logic functions once", async () => {
      const logger = vi.fn();
      await runInit({ config: mockConfig, logger });

      expect(
        loadJwksWithX5C,
        "Trust Anchor JWKS+x5c should be generated",
      ).toHaveBeenCalledOnce();
      expect(
        loadJwks,
        "wallet_provider JWKS should be loaded/generated",
      ).toHaveBeenCalledWith(
        mockConfig.wallet.backup_storage_path,
        buildJwksPath("wallet_provider"),
      );
      expect(
        loadWalletProviderCertificate,
        "wallet provider cert chain should be built",
      ).toHaveBeenCalledOnce();
      expect(
        loadJwks,
        "wallet_unit JWKS should be loaded/generated",
      ).toHaveBeenCalledWith(
        mockConfig.wallet.backup_storage_path,
        buildJwksPath("wallet_unit"),
      );
      expect(
        loadOrCreateServerCertificate,
        "TLS server certificate should be loaded/generated",
      ).toHaveBeenCalledOnce();
    });

    it("reports all 14 artifacts as 'created'", async () => {
      const loggedLines: string[] = [];
      await runInit({
        config: mockConfig,
        logger: (msg) => loggedLines.push(msg),
      });

      const statusLines = loggedLines.filter(
        (l) =>
          l.includes(":") &&
          !l.startsWith("-") &&
          !l.startsWith("\n") &&
          !l.startsWith("Init"),
      );
      expect(statusLines, "14 artifacts should be reported").toHaveLength(14);
      for (const line of statusLines) {
        expect(line, `expected "created" status in: ${line}`).toMatch(
          /^created\s+:/,
        );
      }
    });

    it("does not call rmSync", async () => {
      await runInit({ config: mockConfig, logger: vi.fn() });
      expect(
        mockRmSync,
        "rmSync should not be called for a fresh init",
      ).not.toHaveBeenCalled();
    });
  });

  describe("idempotent run (all files already exist, force=false)", () => {
    beforeEach(() => {
      mockExistsSync.mockReturnValue(true);
    });

    it("reports all 14 artifacts as 'exists'", async () => {
      const loggedLines: string[] = [];
      await runInit({
        config: mockConfig,
        logger: (msg) => loggedLines.push(msg),
      });

      const statusLines = loggedLines.filter(
        (l) =>
          l.includes(":") &&
          !l.startsWith("-") &&
          !l.startsWith("\n") &&
          !l.startsWith("Init"),
      );
      expect(statusLines, "14 artifacts should be reported").toHaveLength(14);
      for (const line of statusLines) {
        expect(line, `expected "exists" status in: ${line}`).toMatch(
          /^exists\s+:/,
        );
      }
    });

    it("does not call rmSync when force is false", async () => {
      await runInit({ config: mockConfig, force: false, logger: vi.fn() });
      expect(
        mockRmSync,
        "rmSync must not be called without force",
      ).not.toHaveBeenCalled();
    });

    it("still invokes all logic functions", async () => {
      await runInit({ config: mockConfig, logger: vi.fn() });
      expect(loadJwksWithX5C).toHaveBeenCalledOnce();
      expect(loadWalletProviderCertificate).toHaveBeenCalledOnce();
      expect(loadOrCreateServerCertificate).toHaveBeenCalledOnce();
    });
  });

  describe("force overwrite (all files exist, force=true)", () => {
    beforeEach(() => {
      mockExistsSync.mockReturnValue(true);
    });

    it("reports all 14 artifacts as 'overwritten'", async () => {
      const loggedLines: string[] = [];
      await runInit({
        config: mockConfig,
        force: true,
        logger: (msg) => loggedLines.push(msg),
      });

      const statusLines = loggedLines.filter(
        (l) =>
          l.includes(":") &&
          !l.startsWith("-") &&
          !l.startsWith("\n") &&
          !l.startsWith("Init"),
      );
      expect(statusLines, "14 artifacts should be reported").toHaveLength(14);
      for (const line of statusLines) {
        expect(line, `expected "overwritten" status in: ${line}`).toMatch(
          /^overwritten\s+:/,
        );
      }
    });

    it("calls rmSync for each existing file", async () => {
      await runInit({ config: mockConfig, force: true, logger: vi.fn() });
      // 16 ensureFileRemoved calls: 2 TA, 3 WP (jwks + cert + 2 intermediate), 2 WU,
      // 3 PID (issuer jwks + cert + holder jwks), 3 mDL (issuer jwks + cert + device jwks),
      // 2 TLS — each calls rmSync when force=true and existed=true
      expect(
        mockRmSync,
        "rmSync should be called for each existing file",
      ).toHaveBeenCalledTimes(16);
    });

    it("passes { force: true } to rmSync", async () => {
      await runInit({ config: mockConfig, force: true, logger: vi.fn() });
      for (const call of mockRmSync.mock.calls) {
        expect(call[1], "rmSync should be called with { force: true }").toEqual(
          { force: true },
        );
      }
    });
  });

  describe("logger output", () => {
    beforeEach(() => {
      mockExistsSync.mockReturnValue(false);
    });

    it("logs the opening banner", async () => {
      const logger = vi.fn();
      await runInit({ config: mockConfig, logger });
      expect(logger).toHaveBeenCalledWith(
        "Initializing cryptographic artifacts...",
      );
    });

    it("logs the report section headers", async () => {
      const logger = vi.fn();
      await runInit({ config: mockConfig, logger });
      expect(logger).toHaveBeenCalledWith("\nInitialization Report:");
      expect(logger).toHaveBeenCalledWith("-----------------------");
      expect(logger).toHaveBeenCalledWith("Initialization complete.");
    });

    it("uses console.log when no logger is provided", async () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      await runInit({ config: mockConfig });
      expect(consoleSpy).toHaveBeenCalledWith(
        "Initializing cryptographic artifacts...",
      );
      consoleSpy.mockRestore();
    });
  });

  describe("artifact paths", () => {
    beforeEach(() => {
      mockExistsSync.mockReturnValue(false);
    });

    it("passes correct directory and filename to loadJwksWithX5C for Trust Anchor", async () => {
      await runInit({ config: mockConfig, logger: vi.fn() });
      expect(loadJwksWithX5C).toHaveBeenCalledWith(
        mockConfig.trust.federation_trust_anchors_jwks_path,
        "trust_anchor",
        mockConfig.trust.ca_cert_path,
        mockConfig.trust.certificate_subject,
      );
    });

    it("uses issuance.certificate_subject for mDL cert when provided", async () => {
      const configWithIssuerSubject = {
        ...mockConfig,
        issuance: { certificate_subject: "CN=custom_issuer" },
      } as unknown as Config;

      await runInit({ config: configWithIssuerSubject, logger: vi.fn() });

      expect(loadCertificate).toHaveBeenCalledWith(
        mockConfig.wallet.backup_storage_path,
        buildCertPath("mso_mdoc_mDL"),
        expect.anything(),
        "CN=custom_issuer",
      );
    });

    it("falls back to trust.certificate_subject for mDL cert when issuance.certificate_subject is absent", async () => {
      await runInit({ config: mockConfig, logger: vi.fn() });

      expect(loadCertificate).toHaveBeenCalledWith(
        mockConfig.wallet.backup_storage_path,
        buildCertPath("mso_mdoc_mDL"),
        expect.anything(),
        mockConfig.trust.certificate_subject,
      );
    });

    it("uses default TLS cert dir when trust_anchor.tls_cert_dir is not set", async () => {
      const configWithoutTlsDir = {
        ...mockConfig,
        trust_anchor: {},
      } as unknown as Config;

      const loggedLines: string[] = [];
      await runInit({
        config: configWithoutTlsDir,
        logger: (msg) => loggedLines.push(msg),
      });

      const tlsLine = loggedLines.find((l) => l.includes("server.cert.pem"));
      expect(tlsLine, "TLS cert should appear in report").toBeDefined();
      expect(tlsLine).toContain(path.join("./data/backup", "server.cert.pem"));
    });

    it("passes full config to loadOrCreateServerCertificate", async () => {
      await runInit({ config: mockConfig, logger: vi.fn() });
      expect(loadOrCreateServerCertificate).toHaveBeenCalledWith(mockConfig);
    });
  });
});
