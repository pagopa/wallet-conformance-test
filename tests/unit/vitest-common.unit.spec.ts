import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";

import {
  buildIncludePattern,
  createTestConfig,
  resolveConfigPath,
} from "../../vitest.common.js";

const packageRoot = path.resolve(import.meta.dirname, "../..");

function withTempPackageDirs(
  run: (dirs: { launchDir: string; packageDir: string }) => void,
) {
  const launchDir = mkdtempSync(path.join(tmpdir(), "wct-launch-"));
  const packageDir = mkdtempSync(path.join(tmpdir(), "wct-package-"));
  const originalConfigFileIni = process.env.CONFIG_FILE_INI;

  try {
    Reflect.deleteProperty(process.env, "CONFIG_FILE_INI");
    run({ launchDir, packageDir });
  } finally {
    if (originalConfigFileIni === undefined) {
      Reflect.deleteProperty(process.env, "CONFIG_FILE_INI");
    } else {
      process.env.CONFIG_FILE_INI = originalConfigFileIni;
    }
    rmSync(launchDir, { force: true, recursive: true });
    rmSync(packageDir, { force: true, recursive: true });
  }
}

describe("buildIncludePattern", () => {
  it("normalizes Windows paths before building the Vitest glob", () => {
    const includePattern = buildIncludePattern(
      "issuance",
      "D:\\a\\wallet-conformance-test\\wallet-conformance-test\\tests\\conformance\\issuance",
      false,
    );

    expect(includePattern).toBe(
      "D:/a/wallet-conformance-test/wallet-conformance-test/tests/conformance/issuance/**/*.issuance.spec.ts",
    );
  });

  it("keeps user-configured directories compatible with both ts and js tests", () => {
    const includePattern = buildIncludePattern(
      "presentation",
      "D:\\custom\\presentation-tests",
      true,
    );

    expect(includePattern).toBe(
      "D:/custom/presentation-tests/**/*.presentation.spec.{js,ts}",
    );
  });
});

describe("resolveConfigPath", () => {
  it("falls back to package config.ini before config.example.ini", () => {
    withTempPackageDirs(({ launchDir, packageDir }) => {
      const packageConfigPath = path.join(packageDir, "config.ini");
      writeFileSync(
        packageConfigPath,
        "[issuance]\nurl = https://package.example",
      );

      expect(resolveConfigPath(launchDir, packageDir)).toBe(packageConfigPath);
    });
  });

  it("prefers launch directory config.ini over package config.ini", () => {
    withTempPackageDirs(({ launchDir, packageDir }) => {
      const launchConfigPath = path.join(launchDir, "config.ini");
      writeFileSync(
        launchConfigPath,
        "[issuance]\nurl = https://launch.example",
      );
      writeFileSync(
        path.join(packageDir, "config.ini"),
        "[issuance]\nurl = https://package.example",
      );

      expect(resolveConfigPath(launchDir, packageDir)).toBe(launchConfigPath);
    });
  });
});

describe("createTestConfig", () => {
  it("anchors Vitest root and setup files to the package root", () => {
    const config = createTestConfig("issuance");

    expect(config.root).toBe(packageRoot);
    expect(config.test?.globalSetup).toBe(
      path.join(packageRoot, "tests/global-setup.ts"),
    );
    expect(config.test?.setupFiles).toEqual([
      path.join(packageRoot, "tests/setup-tls.ts"),
    ]);
  });
});
