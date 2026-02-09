import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { existsSync, readFileSync } from "node:fs";
import path from "path";

import { Config, configSchema } from "@/types";

/**
 * Command-line options that can override configuration
 */
export interface CliOptions {
  [key: string]: boolean | number | string | undefined;
  credentialIssuerUri?: string;
  credentialTypes?: string;
  fileIni?: string;
  issuanceTestsDir?: string;
  logFile?: string;
  logLevel?: string;
  maxRetries?: number;
  port?: number;
  presentationAuthorizeUri?: string;
  presentationTestsDir?: string;
  saveCredential?: boolean;
  stepsMapping?: string;
  timeout?: number;
}

/**
 * Legacy function for backward compatibility
 * @deprecated Use loadConfigWithHierarchy instead
 * @param fileName The path to the INI configuration file.
 * @returns The parsed configuration object.
 */
export function loadConfig(fileName: string): Config {
  return loadConfigWithHierarchy({}, fileName);
}

/**
 * Loads configuration with hierarchical priority:
 * 1. Command-Line Options (Highest priority)
 * 2. Custom .ini File (--file-ini)
 * 3. Default .ini File (Lowest priority)
 *
 * @param options CLI options including optional custom INI file path (if not provided, reads from environment)
 * @param defaultIniPath Path to the default INI file (defaults to ./config.ini)
 * @returns The merged and validated configuration object
 */
export function loadConfigWithHierarchy(
  options: CliOptions | null = null,
  defaultIniPath = "./config.ini",
): Config {
  // If no options provided, read from environment variables
  const cliOptions = options ?? readCliOptionsFromEnv();

  // Step 1: Load default config.ini (lowest priority)
  const defaultIniAbsPath = path.resolve(process.cwd(), defaultIniPath);
  const defaultConfig = loadIniFile(defaultIniAbsPath);

  if (!defaultConfig) {
    throw new Error(
      `Default configuration file not found at ${defaultIniAbsPath}. Please ensure config.ini exists.`,
    );
  }

  // Step 2: Load custom ini file if specified (medium priority)
  let customConfig: null | Partial<Config> = null;
  if (cliOptions.fileIni) {
    const customIniPath = path.resolve(process.cwd(), cliOptions.fileIni);
    customConfig = loadIniFile(customIniPath);

    if (!customConfig) {
      throw new Error(
        `Custom configuration file not found at ${customIniPath}`,
      );
    }
  }

  // Step 3: Convert CLI options to config format (highest priority)
  const cliConfig = cliOptionsToConfig(cliOptions);

  // Step 4: Merge configurations in priority order
  let mergedConfig = defaultConfig;

  if (customConfig) {
    mergedConfig = deepMerge(mergedConfig, customConfig);
  }

  if (Object.keys(cliConfig).length > 0) {
    mergedConfig = deepMerge(mergedConfig, cliConfig);
  }

  // Step 5: Validate the final configuration
  try {
    const validatedConfig = parseWithErrorHandling(configSchema, mergedConfig);
    return validatedConfig;
  } catch (e) {
    const err = e as Error;
    throw new Error(
      `Configuration validation failed: ${err.message}\n\n` +
        `Please ensure all mandatory fields are defined in either:\n` +
        `- Default INI file (${defaultIniPath})\n` +
        `- Custom INI file (${cliOptions.fileIni || "not specified"})\n` +
        `- Command-line options\n\n` +
        `Configuration hierarchy:\n` +
        `1. Command-Line Options (Highest priority)\n` +
        `2. Custom .ini File (--file-ini)\n` +
        `3. Default .ini File (Lowest priority)`,
    );
  }
}

/**
 * Converts CLI options to a partial Config object
 * @param options CLI options
 * @returns Partial configuration object
 * @note The credentialType option is stored in the CliOptions but not mapped to Config
 *       because it's intended for test filtering rather than configuration override.
 *       Test runners should access this value directly from the CliOptions or environment
 *       variables (CONFIG_CREDENTIAL_TYPE) to filter which credential types to test.
 */
function cliOptionsToConfig(options: CliOptions): Partial<Config> {
  const partialConfig: Record<string, any> = {};

  // Map CLI options to config structure
  if (
    options.credentialIssuerUri ||
    options.credentialTypes ||
    options.saveCredential !== undefined ||
    options.issuanceTestsDir
  ) {
    const issuance: Record<string, unknown> = {};
    if (options.credentialIssuerUri) {
      issuance.url = options.credentialIssuerUri;
    }
    if (options.credentialTypes) {
      issuance.credential_types = options.credentialTypes
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0);
    }
    if (options.saveCredential !== undefined) {
      issuance.save_credential = options.saveCredential;
    }
    if (options.issuanceTestsDir) {
      issuance.tests_dir = options.issuanceTestsDir;
    }
    partialConfig.issuance = issuance;
  }
  if (options.presentationAuthorizeUri || options.presentationTestsDir) {
    const presentation: Record<string, unknown> = {};
    if (options.presentationAuthorizeUri) {
      presentation.authorize_request_url = options.presentationAuthorizeUri;
    }
    if (options.presentationTestsDir) {
      presentation.tests_dir = options.presentationTestsDir;
    }
    partialConfig.presentation = presentation;
  }

  if (options.timeout !== undefined || options.maxRetries !== undefined) {
    const network: Record<string, number> = {};
    if (options.timeout !== undefined) {
      network.timeout = options.timeout;
    }
    if (options.maxRetries !== undefined) {
      network.max_retries = options.maxRetries;
    }
    partialConfig.network = network;
  }

  if (options.logLevel || options.logFile) {
    const logging: Record<string, string> = {};
    if (options.logLevel) {
      logging.log_level = options.logLevel;
    }
    if (options.logFile) {
      logging.log_file = options.logFile;
    }
    partialConfig.logging = logging;
  }

  if (options.port !== undefined) {
    partialConfig.trust_anchor = { port: options.port };
  }

  if (options.stepsMapping) {
    const mappings: Record<string, string> = {};
    const pairs = options.stepsMapping.split(",");
    for (const pair of pairs) {
      const [key, value] = pair.split("=").map((s) => s.trim());
      if (key && value) {
        mappings[key] = value;
      }
    }
    if (Object.keys(mappings).length > 0) {
      partialConfig.steps_mapping = {
        mapping: mappings,
      };
    }
  }

  return partialConfig as Partial<Config>;
}

/**
 * Deep merges two objects, with the second object's values taking precedence
 * @param target The target object (lower priority)
 * @param source The source object (higher priority)
 * @returns The merged object
 */
function deepMerge<T>(target: T, source: Partial<T>): T {
  const result = { ...target };

  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
      continue;
    }

    const sourceValue = source[key];
    const targetValue = result[key];

    if (sourceValue === undefined) {
      continue;
    }

    if (
      typeof sourceValue === "object" &&
      sourceValue !== null &&
      !Array.isArray(sourceValue) &&
      typeof targetValue === "object" &&
      targetValue !== null &&
      !Array.isArray(targetValue)
    ) {
      // Recursively merge nested objects
      result[key] = deepMerge(targetValue, sourceValue) as T[Extract<
        keyof T,
        string
      >];
    } else {
      // Override with source value
      result[key] = sourceValue as T[Extract<keyof T, string>];
    }
  }

  return result;
}

/**
 * Loads configuration from an INI file
 * @param filePath Path to the INI file
 * @returns Parsed configuration object or null if file doesn't exist
 */
function loadIniFile(filePath: string): null | Partial<Config> {
  if (!existsSync(filePath)) {
    return null;
  }

  try {
    const textConfig = readFileSync(filePath, "utf-8");
    const parsed = parse(textConfig) as any;

    // Transform steps_mapping from flat structure to nested structure
    // INI format: [steps_mapping] default_steps_dir = ... / key = value
    // Target format: { default_steps_dir: "...", mapping: { key: value } }
    if (parsed.steps_mapping) {
      const { default_steps_dir, ...mappings } = parsed.steps_mapping;
      parsed.steps_mapping = {
        ...(default_steps_dir && { default_steps_dir }),
        mapping: mappings,
      };
    }

    return parsed as Partial<Config>;
  } catch (e) {
    const err = e as Error;
    throw new Error(`Failed to parse INI file ${filePath}: ${err.message}`);
  }
}

/**
 * Reads CLI options from environment variables
 * Environment variables are set by the CLI script
 * @returns CLI options object
 */
function readCliOptionsFromEnv(): CliOptions {
  const options: CliOptions = {};

  if (process.env.CONFIG_FILE_INI) {
    options.fileIni = process.env.CONFIG_FILE_INI;
  }
  if (process.env.CONFIG_CREDENTIAL_ISSUER_URI) {
    options.credentialIssuerUri = process.env.CONFIG_CREDENTIAL_ISSUER_URI;
  }
  if (process.env.CONFIG_PRESENTATION_AUTHORIZE_URI) {
    options.presentationAuthorizeUri =
      process.env.CONFIG_PRESENTATION_AUTHORIZE_URI;
  }
  if (process.env.CONFIG_CREDENTIAL_TYPES) {
    options.credentialTypes = process.env.CONFIG_CREDENTIAL_TYPES;
  }
  if (process.env.CONFIG_TIMEOUT) {
    const parsed = parseInt(process.env.CONFIG_TIMEOUT, 10);
    if (!isNaN(parsed)) {
      options.timeout = parsed;
    }
  }
  if (process.env.CONFIG_MAX_RETRIES) {
    const parsed = parseInt(process.env.CONFIG_MAX_RETRIES, 10);
    if (!isNaN(parsed)) {
      options.maxRetries = parsed;
    }
  }
  if (process.env.CONFIG_LOG_LEVEL) {
    options.logLevel = process.env.CONFIG_LOG_LEVEL;
  }
  if (process.env.CONFIG_LOG_FILE) {
    options.logFile = process.env.CONFIG_LOG_FILE;
  }
  if (process.env.CONFIG_PORT) {
    const parsed = parseInt(process.env.CONFIG_PORT, 10);
    if (!isNaN(parsed)) {
      options.port = parsed;
    }
  }
  if (process.env.CONFIG_SAVE_CREDENTIAL) {
    options.saveCredential = process.env.CONFIG_SAVE_CREDENTIAL === "true";
  }
  if (process.env.CONFIG_ISSUANCE_TESTS_DIR) {
    options.issuanceTestsDir = process.env.CONFIG_ISSUANCE_TESTS_DIR;
  }
  if (process.env.CONFIG_PRESENTATION_TESTS_DIR) {
    options.presentationTestsDir = process.env.CONFIG_PRESENTATION_TESTS_DIR;
  }
  if (process.env.CONFIG_STEPS_MAPPING) {
    options.stepsMapping = process.env.CONFIG_STEPS_MAPPING;
  }

  return options;
}
