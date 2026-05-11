import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  loadConfigWithHierarchy,
  readPackageVersion,
} from "@/logic/config-loader";

const DEFAULT_INI = "./config.example.ini";
const envKeys = [
  "CONFIG_ISSUANCE_CERTIFICATE_SUBJECT",
  "CONFIG_MAX_RETRIES",
  "CONFIG_PORT",
  "CONFIG_SAVE_CREDENTIAL",
  "CONFIG_STEPS_MAPPING",
  "CONFIG_TIMEOUT",
  "CONFIG_UNSAFE_TLS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
];

describe("loadConfigWithHierarchy – user_agent", () => {
  const originalEnv = Object.fromEntries(
    envKeys.map((key) => [key, process.env[key]]),
  );

  beforeEach(() => {
    for (const key of envKeys) {
      Reflect.deleteProperty(process.env, key);
    }
  });

  afterEach(() => {
    for (const key of envKeys) {
      const value = originalEnv[key];
      if (value === undefined) {
        Reflect.deleteProperty(process.env, key);
      } else {
        process.env[key] = value;
      }
    }
  });

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
      HappyFlowIssuance: "tests/steps/issuance",
      HappyFlowPresentation: "tests/steps/presentation",
    });
  });
});
