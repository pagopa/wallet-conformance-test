import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  PID_CREDENTIAL_CONFIGURATION_ID,
  PidIssuanceModeNotConfiguredError,
} from "@/errors";
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { packageRoot } from "@/logic/runtime-paths";
import {
  assertPidIssuanceCredentialGuard,
  isMockMrtdEnabled,
  pidIssuanceSchema,
} from "@/types/pid-issuance";

const DEFAULT_INI = path.join(packageRoot, "config.example.ini");

const originalCwd = process.cwd();
let tempDirs: string[] = [];

function chdirTemp(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "wct-issuance-pid-config-"));
  tempDirs.push(dir);
  process.chdir(dir);
  return dir;
}

beforeEach(() => {
  chdirTemp();
});

afterEach(() => {
  process.chdir(originalCwd);
  for (const dir of tempDirs) {
    rmSync(dir, { force: true, recursive: true });
  }
  tempDirs = [];
});

describe("assertPidIssuanceCredentialGuard (FR-3)", () => {
  it("throws when PID is in credential_types and mode is none", () => {
    expect(() =>
      assertPidIssuanceCredentialGuard([PID_CREDENTIAL_CONFIGURATION_ID], {
        mode: "none",
      }),
    ).toThrow(PidIssuanceModeNotConfiguredError);
  });

  it("allows PID credential_types when mode is l3", () => {
    expect(() =>
      assertPidIssuanceCredentialGuard([PID_CREDENTIAL_CONFIGURATION_ID], {
        mode: "l3",
      }),
    ).not.toThrow();
  });

  it("allows QEA credential_types when mode is none", () => {
    expect(() =>
      assertPidIssuanceCredentialGuard(["dc_sd_jwt_EuropeanDisabilityCard"], {
        mode: "none",
      }),
    ).not.toThrow();
  });
});

describe("isMockMrtdEnabled", () => {
  it("returns false when mode is none and flag is unset", () => {
    expect(isMockMrtdEnabled({ mode: "none" })).toBe(false);
  });

  it("returns true when mode is l3 and flag is unset", () => {
    expect(isMockMrtdEnabled({ mode: "l3" })).toBe(true);
  });

  it("honours explicit mock_mrtd_enabled=false over mode l3", () => {
    expect(isMockMrtdEnabled({ mock_mrtd_enabled: false, mode: "l3" })).toBe(
      false,
    );
  });

  it("honours explicit mock_mrtd_enabled=true over mode none", () => {
    expect(isMockMrtdEnabled({ mock_mrtd_enabled: true, mode: "none" })).toBe(
      true,
    );
  });
});

describe("pidIssuanceSchema", () => {
  it("requires core identity fields when mode is l3", () => {
    const result = pidIssuanceSchema.safeParse({ mode: "l3" });

    expect(result.success).toBe(false);
    if (result.success) {
      return;
    }
    expect(
      result.error.issues.some((issue) => issue.path.includes("given_name")),
    ).toBe(true);
  });

  it("requires mrz and NUN when mode is l2plus", () => {
    const result = pidIssuanceSchema.safeParse({
      birthdate: "1980-01-10",
      family_name: "Rossi",
      given_name: "Mario",
      mode: "l2plus",
      place_of_birth: "Roma",
      tax_id_code: "RSSMRA80A10H501Z",
    });

    expect(result.success).toBe(false);
    if (result.success) {
      return;
    }
    const paths = result.error.issues.map((issue) => issue.path.join("."));
    expect(paths).toContain("mrz");
    expect(paths).toContain("personal_administrative_number");
  });

  it("accepts a complete l3 identity block", () => {
    const result = pidIssuanceSchema.safeParse({
      birthdate: "1980-01-10",
      family_name: "Rossi",
      given_name: "Mario",
      mode: "l3",
      place_of_birth: "Roma",
      tax_id_code: "RSSMRA80A10H501Z",
    });

    expect(result.success).toBe(true);
  });

  it("accepts mock_authorize_code when mode is l3 (B1-7.2)", () => {
    const result = pidIssuanceSchema.safeParse({
      birthdate: "1980-01-10",
      family_name: "Rossi",
      given_name: "Mario",
      mock_authorize_code: "test-auth-code-123",
      mode: "l3",
      place_of_birth: "Roma",
      tax_id_code: "RSSMRA80A10H501Z",
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }
    expect(result.data.mock_authorize_code).toBe("test-auth-code-123");
  });

  it("rejects mock_authorize_code when mode is l2plus (B1-7.2)", () => {
    const result = pidIssuanceSchema.safeParse({
      birthdate: "1980-01-10",
      family_name: "Rossi",
      given_name: "Mario",
      mock_authorize_code: "test-auth-code-123",
      mode: "l2plus",
      mrz: "IDITARSSMRA80A10H501Z<<<<<<<<<<<<<<<",
      personal_administrative_number: "XX00000XX",
      place_of_birth: "Roma",
      tax_id_code: "RSSMRA80A10H501Z",
    });

    expect(result.success).toBe(false);
    if (result.success) {
      return;
    }
    const paths = result.error.issues.map((issue) => issue.path.join("."));
    expect(paths).toContain("mock_authorize_code");
  });
});

describe("loadConfigWithHierarchy – issuance_pid FR-3", () => {
  it("throws PidIssuanceModeNotConfiguredError for PID + mode none", () => {
    writeFileSync(
      path.join(process.cwd(), "config.ini"),
      [
        "[issuance]",
        "url = https://pid-provider.example",
        `credential_types[] = ${PID_CREDENTIAL_CONFIGURATION_ID}`,
        "",
        "[issuance_pid]",
        "mode = none",
      ].join("\n"),
    );

    expect(() => loadConfigWithHierarchy({}, DEFAULT_INI)).toThrow(
      PidIssuanceModeNotConfiguredError,
    );
  });

  it("loads when PID is requested with mode l3 and identity fields", () => {
    writeFileSync(
      path.join(process.cwd(), "config.ini"),
      [
        "[issuance]",
        "url = https://pid-provider.example",
        `credential_types[] = ${PID_CREDENTIAL_CONFIGURATION_ID}`,
        "",
        "[issuance_pid]",
        "mode = l3",
        "given_name = Mario",
        "family_name = Rossi",
        "tax_id_code = RSSMRA80A10H501Z",
        "birthdate = 1980-01-10",
        "place_of_birth = Roma",
      ].join("\n"),
    );

    const config = loadConfigWithHierarchy({}, DEFAULT_INI);

    expect(config.issuance_pid.mode).toBe("l3");
    expect(config.issuance.credential_types).toContain(
      PID_CREDENTIAL_CONFIGURATION_ID,
    );
  });

  it("loads mock_authorize_code for mode l3 (B1-7.2)", () => {
    writeFileSync(
      path.join(process.cwd(), "config.ini"),
      [
        "[issuance]",
        "url = https://pid-provider.example",
        `credential_types[] = ${PID_CREDENTIAL_CONFIGURATION_ID}`,
        "",
        "[issuance_pid]",
        "mode = l3",
        "given_name = Mario",
        "family_name = Rossi",
        "tax_id_code = RSSMRA80A10H501Z",
        "birthdate = 1980-01-10",
        "place_of_birth = Roma",
        "mock_authorize_code = my-static-test-code",
      ].join("\n"),
    );

    const config = loadConfigWithHierarchy({}, DEFAULT_INI);

    expect(config.issuance_pid.mode).toBe("l3");
    expect(config.issuance_pid.mock_authorize_code).toBe(
      "my-static-test-code",
    );
  });

  it("loads QEA profile with mode none (regression)", () => {
    writeFileSync(
      path.join(process.cwd(), "config.ini"),
      [
        "[issuance]",
        "url = https://issuer.example",
        "credential_types[] = dc_sd_jwt_EuropeanDisabilityCard",
        "",
        "[issuance_pid]",
        "mode = none",
      ].join("\n"),
    );

    const config = loadConfigWithHierarchy({}, DEFAULT_INI);

    expect(config.issuance_pid.mode).toBe("none");
    expect(config.issuance.credential_types).toEqual([
      "dc_sd_jwt_EuropeanDisabilityCard",
    ]);
  });
});
