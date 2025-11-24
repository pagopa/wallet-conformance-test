import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { existsSync, readFileSync } from "node:fs";
import path from "path";

import { Config, configSchema } from "@/types";

/**
 * Command-line options that can override configuration
 */
export interface CliOptions {
  [key: string]: number | string | undefined;
  credentialIssuerUri?: string;
  credentialType?: string;
  fileIni?: string;
  logFile?: string;
  logLevel?: string;
  maxRetries?: number;
  port?: number;
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
 */
function cliOptionsToConfig(options: CliOptions): Partial<Config> {
  const partialConfig: Partial<Config> = {};

  // Map CLI options to config structure
  if (options.credentialIssuerUri) {
    partialConfig.issuance = {
      credentials: { types: {} },
      url: options.credentialIssuerUri,
    };
  }

  if (options.timeout !== undefined || options.maxRetries !== undefined) {
    partialConfig.network = {} as Config["network"];
    if (options.timeout !== undefined) {
      partialConfig.network!.timeout = options.timeout;
    }
    if (options.maxRetries !== undefined) {
      partialConfig.network!.max_retries = options.maxRetries;
    }
  }

  if (options.logLevel || options.logFile) {
    partialConfig.logging = {} as Config["logging"];
    if (options.logLevel) {
      partialConfig.logging!.log_level = options.logLevel;
    }
    if (options.logFile) {
      partialConfig.logging!.log_file = options.logFile;
    }
  }

  if (options.port !== undefined) {
    partialConfig.server = { port: options.port };
  }

  return partialConfig;
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
    return parse(textConfig) as Partial<Config>;
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
  if (process.env.CONFIG_CREDENTIAL_TYPE) {
    options.credentialType = process.env.CONFIG_CREDENTIAL_TYPE;
  }
  if (process.env.CONFIG_TIMEOUT) {
    options.timeout = parseInt(process.env.CONFIG_TIMEOUT, 10);
  }
  if (process.env.CONFIG_MAX_RETRIES) {
    options.maxRetries = parseInt(process.env.CONFIG_MAX_RETRIES, 10);
  }
  if (process.env.CONFIG_LOG_LEVEL) {
    options.logLevel = process.env.CONFIG_LOG_LEVEL;
  }
  if (process.env.CONFIG_LOG_FILE) {
    options.logFile = process.env.CONFIG_LOG_FILE;
  }
  if (process.env.CONFIG_PORT) {
    options.port = parseInt(process.env.CONFIG_PORT, 10);
  }

  return options;
}
