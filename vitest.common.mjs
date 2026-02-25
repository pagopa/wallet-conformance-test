/**
 * Common Vitest configuration factory
 * 
 * Creates test configuration for different test types (issuance, presentation)
 * with automatic tests directory resolution from config.ini
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "ini";
import { configDefaults, defineConfig } from "vitest/config";
import "./vitest.global.setup.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
    issuance: "./tests/conformance/issuance",
    presentation: "./tests/conformance/presentation",
  };

  // CLI override via environment variable takes precedence
  const envVar = envVarMap[testType];
  if (process.env[envVar]) {
    return process.env[envVar];
  }

  // Read from config.ini
  try {
    const configPath = process.env.CONFIG_FILE_INI || "./config.ini";
    const configContent = fs.readFileSync(configPath, "utf-8");
    const config = parse(configContent);
    return config[testType]?.tests_dir || defaultDirMap[testType];
  } catch (error) {
    console.warn(
      `Could not read config.ini, using default tests directory: ${defaultDirMap[testType]}`,
    );
    return defaultDirMap[testType];
  }
}

/**
 * Create Vitest configuration for a specific test type
 * 
 * @param {string} testType - Type of test ('issuance' or 'presentation')
 * @returns {import('vitest/config').UserConfig} Vitest configuration
 */
export function createTestConfig(testType) {
  const testsDir = getTestsDir(testType);
  const includePattern = `${testsDir}/**/*.${testType}.spec.ts`;

  console.log(`[${testType}] Tests directory: ${testsDir}`);
  console.log(`[${testType}] Include pattern: ${includePattern}`);

  return defineConfig({
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
        "#": path.resolve(__dirname, "./tests"),
      },
    },
    test: {
      exclude: configDefaults.exclude,
      globalSetup: "./tests/global-setup.ts",
      hookTimeout: 120000,
      include: [includePattern],
    },
  });
}
