#!/usr/bin/env node
/**
 * CLI Entry Point for wct (Wallet Conformance Test)
 *
 * This script handles command-line arguments and passes configuration options
 * to the test runners via environment variables.
 */

import { execSync } from "child_process";
import { Command } from "commander";
import { resolve } from "path";

/**
 * Sets environment variables from CLI options
 * @param options Commander options object
 * @returns Updated environment object
 */
function setEnvFromOptions(options: any): NodeJS.ProcessEnv {
  const env = { ...process.env };

  if (options.fileIni) {
    env.CONFIG_FILE_INI = resolve(process.cwd(), options.fileIni);
  }
  if (options.credentialIssuerUri) {
    env.CONFIG_CREDENTIAL_ISSUER_URI = options.credentialIssuerUri;
  }
  if (options.presentationAuthorizeUri) {
    env.CONFIG_PRESENTATION_AUTHORIZE_URI = options.presentationAuthorizeUri;
  }
  if (options.credentialTypes) {
    env.CONFIG_CREDENTIAL_TYPES = options.credentialTypes;
  }
  if (options.timeout !== undefined) {
    env.CONFIG_TIMEOUT = options.timeout.toString();
  }
  if (options.maxRetries !== undefined) {
    env.CONFIG_MAX_RETRIES = options.maxRetries.toString();
  }
  if (options.logLevel) {
    env.CONFIG_LOG_LEVEL = options.logLevel;
  }
  if (options.logFile) {
    env.CONFIG_LOG_FILE = options.logFile;
  }
  if (options.port !== undefined) {
    env.CONFIG_PORT = options.port.toString();
  }
  if (options.saveCredential !== undefined) {
    env.CONFIG_SAVE_CREDENTIAL = options.saveCredential.toString();
  }

  return env;
}

const program = new Command();

program
  .name("wct")
  .description("Automated conformance testing for IT Wallet ecosystem services")
  .version("1.0.0");

// Common options for all test commands
function addCommonOptions(command: Command): Command {
  return command
    .option("--file-ini <path>", "Path to custom INI configuration file")
    .option(
      "--credential-issuer-uri <uri>",
      "Override the credential issuer URL",
    )
    .option(
      "--presentation-authorize-uri <uri>",
      "Override the presentation authorize URL",
    )
    .option(
      "--credential-types <types>",
      "Comma-separated list of credential configuration IDs to test",
    )
    .option("--timeout <seconds>", "Network timeout in seconds", (val) =>
      parseInt(val, 10),
    )
    .option(
      "--max-retries <number>",
      "Maximum number of retry attempts",
      (val) => parseInt(val, 10),
    )
    .option("--log-level <level>", "Logging level (DEBUG, INFO, WARN, ERROR)")
    .option("--log-file <path>", "Path to log file")
    .option("--port <number>", "Trust Anchor server port", (val) =>
      parseInt(val, 10),
    )
    .option(
      "--save-credential",
      "Save the received credential to disk after test issuance",
    );
}

// Test Issuance Flow
const testIssuance = program
  .command("test:issuance")
  .description("Run credential issuance flow tests");

addCommonOptions(testIssuance);

testIssuance.action((options) => {
  const env = setEnvFromOptions(options);

  try {
    execSync("pnpm test:issuance", {
      env,
      stdio: "inherit",
    });
  } catch {
    process.exit(1);
  }
});

// Test Presentation Flow
const testPresentation = program
  .command("test:presentation")
  .description("Run remote presentation flow tests");

addCommonOptions(testPresentation);

testPresentation.action((options) => {
  const env = setEnvFromOptions(options);

  try {
    execSync("pnpm test:presentation", {
      env,
      stdio: "inherit",
    });
  } catch {
    process.exit(1);
  }
});

// Parse command-line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
