#!/usr/bin/env node
/**
 * CLI Entry Point for wct (Wallet Conformance Test)
 *
 * This script handles command-line arguments and passes configuration options
 * to the test runners via environment variables.
 */

import { Command } from "commander";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";

import type { CliOptions } from "@/logic";

import { packageRoot, readPackageVersion } from "@/logic/runtime-paths";

const nodeRequire = createRequire(import.meta.url);
const experimentalWarningFlag = "--disable-warning=ExperimentalWarning";

function applyEnvOption(
  env: NodeJS.ProcessEnv,
  key: string,
  value: boolean | number | string | undefined,
): void {
  if (value !== undefined) {
    env[key] = String(value);
  }
}

function ensureExperimentalWarningsDisabled(): void {
  if (
    process.env.NODE_OPTIONS?.split(/\s+/).includes(experimentalWarningFlag)
  ) {
    return;
  }

  const result = spawnSync(process.execPath, process.argv.slice(1), {
    env: {
      ...process.env,
      NODE_OPTIONS: getNodeOptionsWithExperimentalWarningDisabled(
        process.env.NODE_OPTIONS,
      ),
    },
    shell: process.platform === "win32",
    stdio: "inherit",
  });

  process.exit(result.status ?? 1);
}

function getNodeOptionsWithExperimentalWarningDisabled(
  nodeOptions: string | undefined,
): string {
  return [nodeOptions, experimentalWarningFlag].filter(Boolean).join(" ");
}

function runTestCommand(
  script: "test:issuance" | "test:presentation",
  options: CliOptions,
) {
  const env = setEnvFromOptions(options);
  const tests = env.TESTS?.split(/\s*,\s*/g).filter((i) => i.length > 0) ?? [];
  const configFile =
    script === "test:issuance"
      ? "vitest.issuance.config.js"
      : "vitest.presentation.config.js";
  const vitestBin = nodeRequire.resolve("vitest/vitest.mjs");

  const result = spawnSync(
    process.execPath,
    [vitestBin, "run", "--config", join(packageRoot, configFile), ...tests],
    {
      env,
      shell: process.platform === "win32",
      stdio: "inherit",
    },
  );

  if (result.error || result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

/**
 * Sets environment variables from CLI options
 * @param options Commander options object
 * @returns Updated environment object
 */
function setEnvFromOptions(options: CliOptions): NodeJS.ProcessEnv {
  const env = { ...process.env };

  env.NODE_OPTIONS = getNodeOptionsWithExperimentalWarningDisabled(
    env.NODE_OPTIONS,
  );

  if (options.fileIni) {
    env.CONFIG_FILE_INI = resolve(process.cwd(), options.fileIni);
  }

  applyEnvOption(
    env,
    "CONFIG_CREDENTIAL_ISSUER_URI",
    options.credentialIssuerUri,
  );
  applyEnvOption(
    env,
    "CONFIG_CREDENTIAL_OFFER_URI",
    options.credentialOfferUri,
  );
  applyEnvOption(
    env,
    "CONFIG_PRESENTATION_AUTHORIZE_URI",
    options.presentationAuthorizeUri,
  );
  applyEnvOption(env, "CONFIG_CREDENTIAL_TYPES", options.credentialTypes);
  applyEnvOption(env, "CONFIG_TIMEOUT", options.timeout);
  applyEnvOption(env, "CONFIG_MAX_RETRIES", options.maxRetries);
  applyEnvOption(env, "CONFIG_LOG_LEVEL", options.logLevel);
  applyEnvOption(env, "CONFIG_LOG_FILE", options.logFile);
  applyEnvOption(env, "CONFIG_PORT", options.port);
  applyEnvOption(env, "CONFIG_SAVE_CREDENTIAL", options.saveCredential);
  applyEnvOption(env, "CONFIG_ISSUANCE_TESTS_DIR", options.issuanceTestsDir);
  applyEnvOption(
    env,
    "CONFIG_ISSUANCE_CERTIFICATE_SUBJECT",
    options.issuanceCertificateSubject,
  );
  applyEnvOption(
    env,
    "CONFIG_PRESENTATION_TESTS_DIR",
    options.presentationTestsDir,
  );
  applyEnvOption(env, "CONFIG_STEPS_MAPPING", options.stepsMapping);
  applyEnvOption(env, "CONFIG_UNSAFE_TLS", options.unsafeTls);
  applyEnvOption(env, "TESTS", options.tests);
  applyEnvOption(env, "CONFIG_WALLET_VERSION", options.walletVersion);
  applyEnvOption(env, "CONFIG_REFRESH_TOKEN", options.refreshToken);
  applyEnvOption(
    env,
    "CONFIG_REFRESH_TOKEN_DEFERRED",
    options.refreshTokenDeferred,
  );
  applyEnvOption(env, "CONFIG_TRANSACTION_ID", options.transactionId);
  applyEnvOption(env, "CONFIG_TRUST_ANCHOR_VERIFY", options.trustAnchorVerify);

  return env;
}

const program = new Command();

program
  .name("wct")
  .description("Automated conformance testing for IT Wallet ecosystem services")
  .version(readPackageVersion());

// Common options for all test commands
function addCommonOptions(command: Command): Command {
  return command
    .option(
      "--file-ini <path>",
      "Path to custom INI configuration file (env: CONFIG_FILE_INI)",
    )
    .option(
      "--credential-issuer-uri <uri>",
      "Override the credential issuer URL (env: CONFIG_CREDENTIAL_ISSUER_URI)",
    )
    .option(
      "--credential-offer-uri <uri>",
      "Override the credential offer URL (env: CONFIG_CREDENTIAL_OFFER_URI)",
    )
    .option(
      "--presentation-authorize-uri <uri>",
      "Override the presentation authorize URL (env: CONFIG_PRESENTATION_AUTHORIZE_URI)",
    )
    .option(
      "--credential-types <types>",
      "Comma-separated list of credential configuration IDs to test (env: CONFIG_CREDENTIAL_TYPES)",
    )
    .option(
      "--timeout <seconds>",
      "Network timeout in seconds (env: CONFIG_TIMEOUT)",
      (val) => parseInt(val, 10),
    )
    .option(
      "--max-retries <number>",
      "Maximum number of retry attempts (env: CONFIG_MAX_RETRIES)",
      (val) => parseInt(val, 10),
    )
    .option(
      "--log-level <level>",
      "Logging level (DEBUG, INFO, WARN, ERROR) (env: CONFIG_LOG_LEVEL)",
    )
    .option("--log-file <path>", "Path to log file (env: CONFIG_LOG_FILE)")
    .option(
      "--port <number>",
      "Trust Anchor server port (env: CONFIG_PORT)",
      (val) => parseInt(val, 10),
    )
    .option(
      "--save-credential",
      "Save the received credential to disk after test issuance (env: CONFIG_SAVE_CREDENTIAL)",
    )
    .option(
      "--issuance-tests-dir <path>",
      "Override directory for issuance test specs (env: CONFIG_ISSUANCE_TESTS_DIR)",
    )
    .option(
      "--issuance-certificate-subject <string>",
      "Override mock issuer's certificate subject (e.g. 'CN=test-issuer.com,OU=issuance,S=IT') (env: CONFIG_ISSUANCE_CERTIFICATE_SUBJECT)",
    )
    .option(
      "--presentation-tests-dir <path>",
      "Override directory for presentation test specs (env: CONFIG_PRESENTATION_TESTS_DIR)",
    )
    .option(
      "--steps-mapping <mapping>",
      "Override steps mapping as comma-separated key=value pairs (e.g., HappyFlowIssuance=./tests/steps/v1/issuance,HappyFlowPresentation=./tests/steps/v1/presentation) (env: CONFIG_STEPS_MAPPING)",
    )
    .option(
      "--unsafe-tls",
      "Disable TLS certificate verification (for local self-signed certs). Sets tls_reject_unauthorized=false (env: CONFIG_UNSAFE_TLS).",
    )
    .option(
      "--trust-anchor-verify <bool>",
      "Set to false to skip tests that require Trust Anchor verification (CI_003, CI_004, RPR-10). Defaults to true (env: CONFIG_TRUST_ANCHOR_VERIFY).",
      (val) => val !== "false",
    )
    .option(
      "--tests <names>",
      "Comma separated list of test names, only the specified tests will be run (env: TESTS)",
    )
    .option(
      "--wallet-version <version>",
      "Override the IT Wallet specification version (V1_0, V1_3, V1_4) (env: CONFIG_WALLET_VERSION)",
    )
    .option(
      "--refresh-token <token>",
      "Use a DPoP-bound Refresh Token to run the Re-Issuance Flow (env: CONFIG_REFRESH_TOKEN)",
    )
    .option(
      "--refresh-token-deferred <token>",
      "DPoP-bound Refresh Token used to obtain a new access token for the Deferred Issuance Flow (env: CONFIG_REFRESH_TOKEN_DEFERRED)",
    )
    .option(
      "--transaction-id <id>",
      "Transaction ID returned in the pending credential response, required for the Deferred Issuance Flow (env: CONFIG_TRANSACTION_ID)",
    );
}

// Test Issuance Flow
const testIssuance = program
  .command("test:issuance")
  .description("Run credential issuance flow tests");

addCommonOptions(testIssuance);

testIssuance.action((options) => {
  runTestCommand("test:issuance", options);
});

// Test Presentation Flow
const testPresentation = program
  .command("test:presentation")
  .description("Run remote presentation flow tests");

addCommonOptions(testPresentation);

testPresentation.action((options) => {
  runTestCommand("test:presentation", options);
});

const report = program
  .command("report")
  .description("Manage conformance test reports");

report
  .command("list")
  .alias("ls")
  .description("List all conformance test runs")
  .action(async () => {
    const { reportList } = await import("@/report/commands/report-list");
    reportList();
  });

report
  .command("create <run_id|latest> <format>")
  .description(
    "Generate an HTML or PDF conformance report for a run ID or the latest run",
  )
  .option(
    "--view <view>",
    "Which view to render: both (default), executive, or technical",
    "both",
  )
  .action(async (runId, format, options) => {
    const { reportCreate } = await import("@/report/commands/report-create");
    await reportCreate(runId, format, options.view);
  });

ensureExperimentalWarningsDisabled();

// Parse command-line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
