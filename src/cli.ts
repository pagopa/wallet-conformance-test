#!/usr/bin/env node
/**
 * CLI Entry Point for wallet-conformance-test
 *
 * This script handles command-line arguments and passes configuration options
 * to the test runners via environment variables.
 */

import { Command } from "commander";
import { execSync } from "child_process";
import { resolve } from "path";

const program = new Command();

program
  .name("wallet-conformance-test")
  .description("Automated conformance testing for IT Wallet ecosystem services")
  .version("1.0.0");

// Common options for all test commands
function addCommonOptions(command: Command): Command {
  return command
    .option("--file-ini <path>", "Path to custom INI configuration file")
    .option("--credential-issuer-uri <uri>", "Override the credential issuer URL")
    .option("--timeout <seconds>", "Network timeout in seconds", (val) => parseInt(val, 10))
    .option("--max-retries <number>", "Maximum number of retry attempts", (val) => parseInt(val, 10))
    .option("--log-level <level>", "Logging level (DEBUG, INFO, WARN, ERROR)")
    .option("--log-file <path>", "Path to log file")
    .option("--port <number>", "Trust Anchor server port", (val) => parseInt(val, 10));
}

// Test Issuance Flow
const testIssuance = program
  .command("test:issuance")
  .description("Run credential issuance flow tests")
  .option("--credential-type <type>", "Credential type to test (e.g., PersonIdentificationData)");

addCommonOptions(testIssuance);

testIssuance.action((options) => {
  // Set environment variables for the configuration options
  const env = { ...process.env };

  if (options.fileIni) {
    env.CONFIG_FILE_INI = resolve(process.cwd(), options.fileIni);
  }
  if (options.credentialIssuerUri) {
    env.CONFIG_CREDENTIAL_ISSUER_URI = options.credentialIssuerUri;
  }
  if (options.credentialType) {
    env.CONFIG_CREDENTIAL_TYPE = options.credentialType;
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

  try {
    execSync("pnpm test:issuance", {
      stdio: "inherit",
      env,
    });
  } catch (error) {
    process.exit(1);
  }
});

// Test Presentation Flow
const testPresentation = program
  .command("test:presentation")
  .description("Run remote presentation flow tests");

addCommonOptions(testPresentation);

testPresentation.action((options) => {
  // Set environment variables for the configuration options
  const env = { ...process.env };

  if (options.fileIni) {
    env.CONFIG_FILE_INI = resolve(process.cwd(), options.fileIni);
  }
  if (options.credentialIssuerUri) {
    env.CONFIG_CREDENTIAL_ISSUER_URI = options.credentialIssuerUri;
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

  try {
    execSync("pnpm test:presentation", {
      stdio: "inherit",
      env,
    });
  } catch (error) {
    process.exit(1);
  }
});

// Parse command-line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
