import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  loadConfigWithHierarchy,
  readPackageVersion,
} from "@/logic/config-loader";
import { packageRoot } from "@/logic/runtime-paths";

const DEFAULT_INI = path.join(packageRoot, "config.example.ini");
const envKeys = [
  "CONFIG_FILE_INI",
  "CONFIG_ISSUANCE_TESTS_DIR",
  "CONFIG_ISSUANCE_CERTIFICATE_SUBJECT",
  "CONFIG_LOG_FILE",
  "CONFIG_MAX_RETRIES",
  "CONFIG_PRESENTATION_TESTS_DIR",
  "CONFIG_PORT",
  "CONFIG_SAVE_CREDENTIAL",
  "CONFIG_STEPS_MAPPING",
  "CONFIG_TIMEOUT",
  "CONFIG_UNSAFE_TLS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
];

const originalEnv = Object.fromEntries(
  envKeys.map((key) => [key, process.env[key]]),
);
const originalCwd = process.cwd();
let tempDirs: string[] = [];

function chdirTemp() {
  const dir = mkdtempSync(path.join(tmpdir(), "wct-config-loader-"));
  tempDirs.push(dir);
  process.chdir(dir);
  return dir;
}

beforeEach(() => {
  for (const key of envKeys) {
    Reflect.deleteProperty(process.env, key);
  }
  chdirTemp();
});

afterEach(() => {
  process.chdir(originalCwd);
  for (const key of envKeys) {
    const value = originalEnv[key];
    if (value === undefined) {
      Reflect.deleteProperty(process.env, key);
    } else {
      process.env[key] = value;
    }
  }
  for (const dir of tempDirs) {
    rmSync(dir, { force: true, recursive: true });
  }
  tempDirs = [];
});

describe("loadConfigWithHierarchy – environment overrides", () => {
  it("should always set user_agent to CEN-TC-Wallet-CLI/<version> from package.json", () => {
    const config = loadConfigWithHierarchy({}, DEFAULT_INI);
    expect(config.network.user_agent).toBe(
      `CEN-TC-Wallet-CLI/${readPackageVersion()}`,
    );
  });

  it("should map issuance certificate subject from environment", () => {
    process.env.CONFIG_ISSUANCE_CERTIFICATE_SUBJECT =
      "CN=test-issuer.example, O=PagoPA";

    const config = loadConfigWithHierarchy(null, DEFAULT_INI);

    expect(config.issuance.certificate_subject).toBe(
      "CN=test-issuer.example, O=PagoPA",
    );
  });

  it("should parse numeric and boolean environment overrides", () => {
    process.env.CONFIG_TIMEOUT = "42";
    process.env.CONFIG_MAX_RETRIES = "7";
    process.env.CONFIG_PORT = "3101";
    process.env.CONFIG_SAVE_CREDENTIAL = "true";
    process.env.CONFIG_UNSAFE_TLS = "true";

    const config = loadConfigWithHierarchy(null, DEFAULT_INI);

    expect(config.network.timeout).toBe(42);
    expect(config.network.max_retries).toBe(7);
    expect(config.trust_anchor.port).toBe(3101);
    expect(config.issuance.save_credential).toBe(true);
    expect(config.network.tls_reject_unauthorized).toBe(false);
  });

  it("should parse comma-separated step mappings from environment", () => {
    process.env.CONFIG_STEPS_MAPPING =
      "HappyFlowIssuance=tests/steps/issuance,HappyFlowPresentation=tests/steps/presentation";

    const config = loadConfigWithHierarchy(null, DEFAULT_INI);

    expect(config.steps_mapping.mapping).toEqual({
      HappyFlowIssuance: path.join(process.cwd(), "tests/steps/issuance"),
      HappyFlowPresentation: path.join(
        process.cwd(),
        "tests/steps/presentation",
      ),
    });
  });
});

describe("loadConfigWithHierarchy – path resolution", () => {
  it("should resolve package fallback data paths under the package root", () => {
    const config = loadConfigWithHierarchy({}, DEFAULT_INI);

    expect(config.wallet.backup_storage_path).toBe(
      path.join(packageRoot, "data/backup"),
    );
    expect(config.wallet.credentials_storage_path).toBe(
      path.join(packageRoot, "data/credentials"),
    );
    expect(config.wallet.wallet_attestations_storage_path).toBe(
      path.join(packageRoot, "data/attestation"),
    );
    expect(config.logging.log_file).toBe(
      path.join(packageRoot, "data/logs/test_run.log"),
    );
  });

  it("should merge implicit local config.ini from the launch directory", () => {
    writeFileSync(
      path.join(process.cwd(), "config.ini"),
      [
        "[logging]",
        "log_file = ./local/logs/test.log",
        "",
        "[issuance]",
        "url = https://local-issuer.example",
      ].join("\n"),
    );

    const config = loadConfigWithHierarchy({}, DEFAULT_INI);

    expect(config.logging.log_file).toBe(
      path.join(process.cwd(), "local/logs/test.log"),
    );
    expect(config.issuance.url).toBe("https://local-issuer.example");
  });

  it("should merge partial runtime sections without requiring path fields", () => {
    writeFileSync(
      path.join(process.cwd(), "config.ini"),
      [
        "[wallet]",
        "wallet_name = Local Wallet",
        "",
        "[trust]",
        "certificate_subject = CN=local-trust",
        "",
        "[logging]",
        "log_level = debug",
      ].join("\n"),
    );

    const config = loadConfigWithHierarchy({}, DEFAULT_INI);

    expect(config.wallet.wallet_name).toBe("Local Wallet");
    expect(config.trust.certificate_subject).toBe("CN=local-trust");
    expect(config.logging.log_level).toBe("debug");
    expect(config.wallet.backup_storage_path).toBe(
      path.join(packageRoot, "data/backup"),
    );
    expect(config.trust.ca_cert_path).toBe(
      path.join(packageRoot, "data/trust_anchor/localhost"),
    );
    expect(config.logging.log_file).toBe(
      path.join(packageRoot, "data/logs/test_run.log"),
    );
  });

  it("should resolve user INI relative paths from the INI directory", () => {
    const configDir = path.join(process.cwd(), "custom");
    const configPath = path.join(configDir, "config.ini");
    mkdirSync(configDir, { recursive: true });
    writeFileSync(
      configPath,
      [
        "[wallet]",
        "backup_storage_path = ./data/backup",
        "credentials_storage_path = ./data/credentials",
        "wallet_attestations_storage_path = ./data/attestation",
        "",
        "[trust]",
        "ca_cert_path = ./trust/ca",
        "federation_trust_anchors_jwks_path = ./trust/jwks",
        "",
        "[trust_anchor]",
        "tls_cert_dir = ./certs",
        "",
        "[logging]",
        "log_file = ./logs/test.log",
        "",
        "[issuance]",
        "tests_dir = ./tests/issuance",
        "",
        "[presentation]",
        "tests_dir = ./tests/presentation",
        "",
        "[steps_mapping]",
        "HappyFlowIssuance = ./steps/issuance",
      ].join("\n"),
    );

    const config = loadConfigWithHierarchy(
      { fileIni: configPath },
      DEFAULT_INI,
    );

    expect(config.wallet.backup_storage_path).toBe(
      path.join(configDir, "data/backup"),
    );
    expect(config.trust.ca_cert_path).toBe(path.join(configDir, "trust/ca"));
    expect(config.trust_anchor.tls_cert_dir).toBe(
      path.join(configDir, "certs"),
    );
    expect(config.logging.log_file).toBe(path.join(configDir, "logs/test.log"));
    expect(config.issuance.tests_dir).toBe(
      path.join(configDir, "tests/issuance"),
    );
    expect(config.presentation.tests_dir).toBe(
      path.join(configDir, "tests/presentation"),
    );
    expect(config.steps_mapping.mapping.HappyFlowIssuance).toBe(
      path.join(configDir, "steps/issuance"),
    );
  });

  it("should resolve CLI path overrides from the launch directory", () => {
    const config = loadConfigWithHierarchy(
      {
        issuanceTestsDir: "./cli-tests/issuance",
        logFile: "./cli/log.txt",
        presentationTestsDir: "./cli-tests/presentation",
        stepsMapping: "HappyFlowIssuance=./cli-steps/issuance",
      },
      DEFAULT_INI,
    );

    expect(config.logging.log_file).toBe(
      path.join(process.cwd(), "cli/log.txt"),
    );
    expect(config.issuance.tests_dir).toBe(
      path.join(process.cwd(), "cli-tests/issuance"),
    );
    expect(config.presentation.tests_dir).toBe(
      path.join(process.cwd(), "cli-tests/presentation"),
    );
    expect(config.steps_mapping.mapping.HappyFlowIssuance).toBe(
      path.join(process.cwd(), "cli-steps/issuance"),
    );
  });
});
