#!/usr/bin/env node
/**
 * CLI Entry Point for wct (Wallet Conformance Test)
 *
 * This script handles command-line arguments and passes configuration options
 * to the test runners via environment variables.
 */

import { Command } from "commander";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

import type { CliOptions } from "@/logic";

import { version } from "../package.json";

function runTestCommand(
  script: "test:issuance" | "test:presentation",
  options: CliOptions,
) {
  const env = setEnvFromOptions(options);
  const tests = env.TESTS?.split(/\s*,\s*/g).filter((i) => i.length > 0) ?? [];

  const result = spawnSync("pnpm", [script, ...tests], {
    env,
    shell: process.platform === "win32",
    stdio: "inherit",
  });

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

  if (options.fileIni) {
    env.CONFIG_FILE_INI = resolve(process.cwd(), options.fileIni);
  }
  if (options.credentialIssuerUri) {
    env.CONFIG_CREDENTIAL_ISSUER_URI = options.credentialIssuerUri;
  }
  if (options.credentialOfferUri) {
    env.CONFIG_CREDENTIAL_OFFER_URI = options.credentialOfferUri;
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
  if (options.issuanceTestsDir) {
    env.CONFIG_ISSUANCE_TESTS_DIR = options.issuanceTestsDir;
  }
  if (options.issuanceCertificateSubject) {
    env.CONFIG_ISSUANCE_CERTIFICATE_SUBJECT =
      options.issuanceCertificateSubject;
  }
  if (options.presentationTestsDir) {
    env.CONFIG_PRESENTATION_TESTS_DIR = options.presentationTestsDir;
  }
  if (options.stepsMapping) {
    env.CONFIG_STEPS_MAPPING = options.stepsMapping;
  }
  if (options.unsafeTls) {
    env.CONFIG_UNSAFE_TLS = "true";
  }
  if (options.externalTaUrl) {
    env.CONFIG_EXTERNAL_TA_URL = options.externalTaUrl;
  }
  if (options.externalTaOnboardingUrl) {
    env.CONFIG_EXTERNAL_TA_ONBOARDING_URL = options.externalTaOnboardingUrl;
  }
  if (options.tests) {
    env.TESTS = options.tests;
  }

  return env;
}

const program = new Command();

program
  .name("wct")
  .description("Automated conformance testing for IT Wallet ecosystem services")
  .version(version);

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
      "--external-ta-url <url>",
      "URL of an external Trust Anchor to register with (env: CONFIG_EXTERNAL_TA_URL)",
    )
    .option(
      "--external-ta-onboarding-url <url>",
      "Onboarding URL of an external Trust Anchor (env: CONFIG_EXTERNAL_TA_ONBOARDING_URL)",
    )
    .option(
      "--tests <names>",
      "Comma separated list of test names, only the specified tests will be run (env: TESTS)",
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

// Parse command-line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
