import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { existsSync, readFileSync } from "node:fs";
import path from "path";

import { Config, configSchema } from "@/types";

import { deepMerge } from "./utils";

/**
 * Command-line options that can override configuration
 */
export interface CliOptions {
  [key: string]: boolean | number | string | undefined;
  bindAddress?: string;
  credentialIssuerUri?: string;
  credentialOfferUri?: string;
  credentialTypes?: string;
  fileIni?: string;
  issuanceCertificateSubject?: string;
  issuanceTestsDir?: string;
  logFile?: string;
  logLevel?: string;
  maxRetries?: number;
  port?: number;
  presentationAuthorizeUri?: string;
  presentationTestsDir?: string;
  saveCredential?: boolean;
  stepsMapping?: string;
  tests?: string;
  timeout?: number;
  trustAnchorCertDir?: string;
  unsafeTls?: boolean;
}

type ConfigSectionBuilder<TSection> = (
  options: CliOptions,
) => Partial<TSection>;

/**
 * Type for parsed INI configuration before transformation
 * The ini parser returns a structure that needs to be transformed to match Config type
 */
type ParsedIniConfig = Record<
  string,
  boolean | number | Record<string, unknown> | string
>;

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

  // Step 4b: Always set user_agent from package.json version at runtime
  mergedConfig.network = deepMerge(mergedConfig.network, {
    user_agent: `CEN-TC-Wallet-CLI/${readPackageVersion()}`,
  });

  // Applies the TLS configuration from the network config to the current process.
  // When tls_reject_unauthorized is false, sets NODE_TLS_REJECT_UNAUTHORIZED=0
  if (mergedConfig.network?.tls_reject_unauthorized === false) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
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
 * Reads the version field from the nearest package.json in the working directory.
 * Returns "0.0.0" if the file cannot be read or the version field is absent.
 */
// NOTE: process.cwd() assumes the CLI/tests are always invoked from the
// repository root. All project scripts (pnpm test, pnpm build, etc.) satisfy
// this assumption, so no directory-walking is needed here.
export function readPackageVersion(): string {
  try {
    const pkgPath = path.resolve(process.cwd(), "package.json");
    const content = readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(content) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * Converts CLI options to a partial Config object.
 *
 * @param options The CLI options to convert.
 * @returns A partial configuration object derived from the CLI options.
 * @note The `credentialType` option is stored in the `CliOptions` but not mapped to `Config`
 *       because it's intended for test filtering rather than configuration override.
 *       Test runners should access this value directly from the `CliOptions` or environment
 *       variables (CONFIG_CREDENTIAL_TYPE) to filter which credential types to test.
 */
function cliOptionsToConfig(options: CliOptions): Partial<Config> {
  const partialConfig: Partial<Config> = {};
  const issuance = buildIssuanceConfig(options);
  const presentation = buildPresentationConfig(options);
  const network = buildNetworkConfig(options);
  const logging = buildLoggingConfig(options);
  const trustAnchor = buildTrustAnchorConfig(options);
  const stepsMapping = buildStepsMappingConfig(options);

  if (hasConfigValues<Config["issuance"]>(issuance)) {
    partialConfig.issuance = issuance as Config["issuance"];
  }
  if (hasConfigValues<Config["presentation"]>(presentation)) {
    partialConfig.presentation = presentation as Config["presentation"];
  }
  if (hasConfigValues<Config["network"]>(network)) {
    partialConfig.network = network as Config["network"];
  }
  if (hasConfigValues<Config["logging"]>(logging)) {
    partialConfig.logging = logging as Config["logging"];
  }
  if (hasConfigValues<Config["trust_anchor"]>(trustAnchor)) {
    partialConfig.trust_anchor = trustAnchor as Config["trust_anchor"];
  }
  if (stepsMapping) {
    partialConfig.steps_mapping = stepsMapping;
  }

  return partialConfig;
}

function hasConfigValues<TSection extends object>(
  section: Partial<TSection>,
): section is Partial<TSection> {
  return Object.keys(section).length > 0;
}

const buildIssuanceConfig: ConfigSectionBuilder<Config["issuance"]> = (
  options,
) => ({
  ...(options.credentialIssuerUri && { url: options.credentialIssuerUri }),
  ...(options.credentialOfferUri && {
    credential_offer_uri: options.credentialOfferUri,
  }),
  ...(options.credentialTypes && {
    credential_types: options.credentialTypes
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0),
  }),
  ...(options.saveCredential !== undefined && {
    save_credential: options.saveCredential,
  }),
  ...(options.issuanceTestsDir && { tests_dir: options.issuanceTestsDir }),
  ...(options.issuanceCertificateSubject && {
    certificate_subject: options.issuanceCertificateSubject,
  }),
});

const buildPresentationConfig: ConfigSectionBuilder<Config["presentation"]> = (
  options,
) => ({
  ...(options.presentationAuthorizeUri && {
    authorize_request_url: options.presentationAuthorizeUri,
  }),
  ...(options.presentationTestsDir && {
    tests_dir: options.presentationTestsDir,
  }),
});

const buildNetworkConfig: ConfigSectionBuilder<Config["network"]> = (
  options,
) => ({
  ...(options.bindAddress !== undefined && {
    bind_address: options.bindAddress,
  }),
  ...(options.timeout !== undefined && { timeout: options.timeout }),
  ...(options.maxRetries !== undefined && {
    max_retries: options.maxRetries,
  }),
  ...(options.unsafeTls !== undefined && {
    tls_reject_unauthorized: !options.unsafeTls,
  }),
});

const buildLoggingConfig: ConfigSectionBuilder<Config["logging"]> = (
  options,
) => ({
  ...(options.logLevel && { log_level: options.logLevel }),
  ...(options.logFile && { log_file: options.logFile }),
});

const buildTrustAnchorConfig: ConfigSectionBuilder<Config["trust_anchor"]> = (
  options,
) => ({
  ...(options.port !== undefined && { port: options.port }),
  ...(options.trustAnchorCertDir !== undefined && {
    tls_cert_dir: options.trustAnchorCertDir,
  }),
});

function buildStepsMappingConfig(
  options: CliOptions,
): Config["steps_mapping"] | undefined {
  if (!options.stepsMapping) {
    return;
  }

  const mappings = Object.fromEntries(
    options.stepsMapping
      .split(",")
      .map((pair) => pair.split("=").map((s) => s.trim()))
      .filter((pair): pair is [string, string] => Boolean(pair[0] && pair[1])),
  );

  return Object.keys(mappings).length > 0 ? { mapping: mappings } : undefined;
}

/**
 * Loads and parses an INI configuration file.
 *
 * @param filePath The path to the INI file.
 * @returns A partial configuration object if the file exists and is parsed successfully, otherwise null.
 * @throws An error if the INI file cannot be parsed.
 */
function loadIniFile(filePath: string): null | Partial<Config> {
  if (!existsSync(filePath)) {
    return null;
  }

  try {
    const textConfig = readFileSync(filePath, "utf-8");
    const parsed = parse(textConfig) as ParsedIniConfig;

    // Transform steps_mapping from flat structure to nested structure
    // INI format: [steps_mapping] key = value
    // Target format: { mapping: { key: value } }
    if (parsed.steps_mapping && typeof parsed.steps_mapping === "object") {
      const stepsMappingRaw = parsed.steps_mapping as Record<string, unknown>;
      parsed.steps_mapping = {
        mapping: stepsMappingRaw as Record<string, string>,
      };
    }

    return parsed as Partial<Config>;
  } catch (e) {
    const err = e as Error;
    throw new Error(`Failed to parse INI file ${filePath}: ${err.message}`);
  }
}

function readBooleanEnv(
  options: CliOptions,
  optionKey: keyof CliOptions,
  envKey: string,
): void {
  const value = process.env[envKey];
  if (value) {
    options[optionKey] = value === "true";
  }
}

/**
 * Reads CLI options from environment variables.
 *
 * This function retrieves configuration settings that have been set as environment
 * variables, typically by a calling script or shell environment. It prefixes
 * the environment variable names with `CONFIG_` to avoid conflicts.
 *
 * @returns A `CliOptions` object populated with values from the environment.
 */
function readCliOptionsFromEnv(): CliOptions {
  const options: CliOptions = {};

  readStringEnv(options, "fileIni", "CONFIG_FILE_INI");
  readStringEnv(options, "credentialIssuerUri", "CONFIG_CREDENTIAL_ISSUER_URI");
  readStringEnv(options, "credentialOfferUri", "CONFIG_CREDENTIAL_OFFER_URI");
  readStringEnv(
    options,
    "presentationAuthorizeUri",
    "CONFIG_PRESENTATION_AUTHORIZE_URI",
  );
  readStringEnv(options, "credentialTypes", "CONFIG_CREDENTIAL_TYPES");
  readNumberEnv(options, "timeout", "CONFIG_TIMEOUT");
  readNumberEnv(options, "maxRetries", "CONFIG_MAX_RETRIES");
  readStringEnv(options, "logLevel", "CONFIG_LOG_LEVEL");
  readStringEnv(options, "logFile", "CONFIG_LOG_FILE");
  readNumberEnv(options, "port", "CONFIG_PORT");
  readBooleanEnv(options, "saveCredential", "CONFIG_SAVE_CREDENTIAL");
  readStringEnv(options, "issuanceTestsDir", "CONFIG_ISSUANCE_TESTS_DIR");
  readStringEnv(
    options,
    "issuanceCertificateSubject",
    "CONFIG_ISSUANCE_CERTIFICATE_SUBJECT",
  );
  readStringEnv(
    options,
    "presentationTestsDir",
    "CONFIG_PRESENTATION_TESTS_DIR",
  );
  readStringEnv(options, "stepsMapping", "CONFIG_STEPS_MAPPING");
  readBooleanEnv(options, "unsafeTls", "CONFIG_UNSAFE_TLS");
  readStringEnv(options, "trustAnchorCertDir", "CONFIG_TRUST_ANCHOR_CERT_DIR");
  readStringEnv(options, "bindAddress", "OIDF_SERVERS_BIND_ADDRESS");

  return options;
}

function readNumberEnv(
  options: CliOptions,
  optionKey: keyof CliOptions,
  envKey: string,
): void {
  const value = process.env[envKey];
  if (!value) {
    return;
  }

  const parsed = parseInt(value, 10);
  if (!isNaN(parsed)) {
    options[optionKey] = parsed;
  }
}

function readStringEnv(
  options: CliOptions,
  optionKey: keyof CliOptions,
  envKey: string,
): void {
  const value = process.env[envKey];
  if (value) {
    options[optionKey] = value;
  }
}
