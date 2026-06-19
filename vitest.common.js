/**
 * Common Vitest configuration factory
 *
 * Creates test configuration for different test types (issuance, presentation)
 * with automatic tests directory resolution from config.ini
 */

import { createConsola } from "consola";
import { parse } from "ini";
import * as fs from "node:fs";
import * as path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { configDefaults, defineConfig } from "vitest/config";

const packageRoot = import.meta.dirname;
const sourceTestsRoot = path.join(packageRoot, "tests");
const builtTestsRoot = path.join(packageRoot, "dist/tests");
const useBuiltTests =
  !fs.existsSync(sourceTestsRoot) && fs.existsSync(builtTestsRoot);
const testsRoot = useBuiltTests ? builtTestsRoot : sourceTestsRoot;
const testFileExtension = useBuiltTests ? "js" : "ts";
const builtReporterPath = path.join(packageRoot, "dist/src/report/reporter.js");
const sourceReporterPath = path.join(packageRoot, "src/report/reporter.ts");
const reporterModulePath = fs.existsSync(builtReporterPath)
  ? builtReporterPath
  : sourceReporterPath;
const { ConformanceReporter } = await import(
  pathToFileURL(reporterModulePath).href
);

const log = createConsola({ level: 3 });

const exclude = buildExcludePatterns(useBuiltTests);

export function buildExcludePatterns(runsBuiltTests) {
  return runsBuiltTests
    ? configDefaults.exclude.filter(
        (pattern) => !["**/dist/**", "**/node_modules/**"].includes(pattern),
      )
    : configDefaults.exclude;
}

export function buildIncludePattern(testType, testsDir, userConfigured) {
  const normalizedTestsDir = testsDir.replace(/\\/g, "/");

  return userConfigured
    ? `${normalizedTestsDir}/**/*.${testType}.spec.{js,ts}`
    : `${normalizedTestsDir}/**/*.${testType}.spec.${useBuiltTests ? "js" : "ts"}`;
}

/**
 * Create Vitest configuration for a specific test type
 *
 * @param {string} testType - Type of test ('issuance' or 'presentation')
 * @returns {import('vitest/config').UserConfig} Vitest configuration
 */
export function createTestConfig(testType) {
  const { testsDir, userConfigured } = getTestsDir(testType);
  const includePattern = buildIncludePattern(
    testType,
    testsDir,
    userConfigured,
  );

  log.debug(`[${testType}] Tests directory: ${testsDir}`);
  log.debug(`[${testType}] Include pattern: ${includePattern}`);

  return defineConfig({
    resolve: {
      alias: {
        "#": useBuiltTests
          ? path.join(packageRoot, "dist/tests")
          : path.join(packageRoot, "tests"),
        "@": useBuiltTests
          ? path.join(packageRoot, "dist/src")
          : path.join(packageRoot, "src"),
      },
    },
    root: packageRoot,
    test: {
      exclude,
      fileParallelism: false,
      globalSetup: path.join(testsRoot, `global-setup.${testFileExtension}`),
      hookTimeout: 120000,
      include: [includePattern],
      reporters: ["dot", new ConformanceReporter(testType)],
      setupFiles: [path.join(testsRoot, `setup-tls.${testFileExtension}`)],
    },
  });
}

export function resolveConfigPath(
  launchDir = process.cwd(),
  rootDir = packageRoot,
) {
  if (process.env.CONFIG_FILE_INI) {
    return path.isAbsolute(process.env.CONFIG_FILE_INI)
      ? process.env.CONFIG_FILE_INI
      : path.resolve(launchDir, process.env.CONFIG_FILE_INI);
  }

  const localConfigPath = path.resolve(launchDir, "config.ini");
  if (fs.existsSync(localConfigPath)) {
    return localConfigPath;
  }

  const packageConfigPath = path.join(rootDir, "config.ini");
  if (fs.existsSync(packageConfigPath)) {
    return packageConfigPath;
  }

  return path.join(rootDir, "config.example.ini");
}

/**
 * Get tests directory for a specific test type
 * Supports CLI override via environment variables
 *
 * @param {string} testType - Type of test ('issuance' or 'presentation')
 * @returns {string} Tests directory path
 */
function getTestsDir(testType) {
  const envVarMap = {
    issuance: "CONFIG_ISSUANCE_TESTS_DIR",
    presentation: "CONFIG_PRESENTATION_TESTS_DIR",
  };

  const defaultDirMap = {
    issuance: useBuiltTests
      ? path.join(packageRoot, "dist/tests/conformance/issuance")
      : path.join(packageRoot, "tests/conformance/issuance"),
    presentation: useBuiltTests
      ? path.join(packageRoot, "dist/tests/conformance/presentation")
      : path.join(packageRoot, "tests/conformance/presentation"),
  };

  // CLI override via environment variable takes precedence
  const envVar = envVarMap[testType];
  if (process.env[envVar]) {
    return {
      testsDir: path.isAbsolute(process.env[envVar])
        ? process.env[envVar]
        : path.resolve(process.cwd(), process.env[envVar]),
      userConfigured: true,
    };
  }

  // Read from config.ini
  try {
    const configPath = resolveConfigPath();
    const configContent = fs.readFileSync(configPath, "utf-8");
    const config = parse(configContent);
    const testsDir = config[testType]?.tests_dir;
    if (!testsDir) {
      return { testsDir: defaultDirMap[testType], userConfigured: false };
    }
    return {
      testsDir: path.isAbsolute(testsDir)
        ? testsDir
        : path.resolve(path.dirname(configPath), testsDir),
      userConfigured: true,
    };
  } catch {
    log.debug(
      `Could not read config.ini, using default tests directory: ${defaultDirMap[testType]}`,
    );
    return { testsDir: defaultDirMap[testType], userConfigured: false };
  }
}
