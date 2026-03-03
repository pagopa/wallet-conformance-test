import {
  ConsolaOptions,
  ConsolaReporter,
  createConsola,
  LogObject,
} from "consola";
import { mkdirSync, openSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { Logger } from "@/types";

import { readPackageVersion } from "./config-loader";

/**
 * Creates a new logger instance with default settings.
 *
 * @returns A new `Logger` instance.
 */
export function createLogger(): Logger {
  return newLogger({
    formatOptions: {
      colors: true,
      columns: 20,
      date: false,
    },
    level: 3,
  });
}

/**
 * Creates a silent logger for use in step sub-runs inside conformance tests.
 * Step-internal logs (start, send, fetch, failure) are suppressed so that
 * only the test-level result lines remain visible in default mode.
 *
 * @returns A `Logger` instance at level 0 (silent).
 */
export function createQuietLogger(): Logger {
  return newLogger({ level: 0 });
}

/**
 * Prints a compact step-progress line:
 *   [N/T] Step Name   ✅  Xms
 *
 * Always emits at info level so it is visible at the default log level.
 *
 * @param index    1-based step index
 * @param total    Total number of steps in the flow
 * @param name     Human-readable step name
 * @param success  Whether the step succeeded
 * @param durationMs  Elapsed time in milliseconds
 */
function flowStep(
  this: Logger,
  index: number,
  total: number,
  name: string,
  success: boolean,
  durationMs: number,
) {
  const counter = `[${index}/${total}]`;
  const icon = success ? "✅" : "❌";
  const duration = `${durationMs}ms`;
  // Pad step name to 25 chars so columns align when names differ in length
  const paddedName = name.padEnd(25, " ");
  this.info(`${counter} ${paddedName} ${icon}  ${duration}`);
}

/**
 * Converts a log level string to its corresponding numeric code.
 *
 * @param level The log level string (e.g., "debug", "info", "error").
 * @returns The numeric code for the log level.
 */
function levelCode(level: string): number {
  switch (level.toLowerCase()) {
    case "debug":
      return 5;
    case "error":
      return 2;
    case "fatal":
      return 1;
    case "silent":
      return 0;
    case "trace":
      return 4;
    case "info":
    default:
      return 3;
  }
}

/**
 * Creates a new logger instance with the specified options.
 *
 * @param options The options to use for the new logger.
 * @returns A new `Logger` instance.
 */
function newLogger(options?: Partial<ConsolaOptions>): Logger {
  return Object.assign(createConsola({ ...options, fancy: true }), {
    flowStep,
    nl,
    setLogOptions,
    testCompleted,
    testFailed,
    testSuite,
    withTag,
  });
}

/**
 * Writes a newline character to the standard output.
 */
function nl() {
  process.stdout.write("\n");
}

/**
 * Sets the log options for the logger.
 *
 * @param this The logger instance.
 * @param options The options to set.
 */
function setLogOptions(
  this: Logger,
  options: { format?: string; level?: string; path?: string },
) {
  const reporters: ConsolaReporter[] = [];
  let formatLog = (logObj: LogObject): string => logObj.message ?? "";

  this.level = levelCode(options.level ?? "fatal");

  if (options.format) {
    const format = options.format;
    formatLog = (logObj: LogObject): string =>
      format
        .replace(/%\(utc\)/, logObj.date.toUTCString())
        .replace(/%\(date\)/, logObj.date.toISOString())
        .replace(/%\(tag\)/, logObj.tag)
        .replace(/%\(levelname\)/, logObj.type.toUpperCase().padEnd(5, " "))
        .replace(/%\(message\)/, logObj.args.join(" ") ?? "");

    reporters.push({
      log: (logObj) => {
        process.stdout.write(`${formatLog(logObj)}\n`);
      },
    });
  }

  if (options.path)
    try {
      mkdirSync(dirname(options.path), { recursive: true });
      const file = openSync(options.path, "w");
      reporters.push({
        log: (logObj) => {
          writeFileSync(file, `${formatLog(logObj)}\n`);
        },
      });
    } catch (e) {
      const err = e as Error;
      this.warn(`Unable to write logs to file ${options.path}: ${err.message}`);
    }

  if (reporters.length > 0) this.setReporters(reporters);
}

/**
 * Prints a single-line test result:
 *   ✅  Issuer correctly rejected PAR with invalid signature   118ms
 *
 * @param id          Test identifier (e.g. "CI_015")
 * @param description Human-readable outcome description
 * @param success     Whether the test passed
 * @param durationMs  Optional elapsed time in milliseconds
 */
function testCompleted(
  this: Logger,
  description: string,
  success: boolean,
  durationMs?: number,
) {
  const icon = success ? "✅" : "❌";
  const timing = durationMs !== undefined ? `   ${durationMs}ms` : "";
  this.info(`${icon}  ${description}${timing}`);
}

/**
 * Logs a "Test failed" message.
 *
 * @param this The logger instance.
 */
function testFailed(this: Logger) {
  this.error("Test failed ❌");
}

/**
 * Prints an ASCII-box boot banner that summarises the test run context:
 *
 *   ┌─────────────────────────────────────────────┐
 *   │  WCT v1.0.2  •  Issuance Conformance Tests  │
 *   │  Target   https://localhost:7071             │
 *   │  Profile  dc_sd_jwt_EuropeanDisabilityCard   │
 *   └─────────────────────────────────────────────┘
 *
 * @param options.title    Test suite title (e.g. "Issuance Conformance Tests")
 * @param options.target   Target URL being tested
 * @param options.profile  Credential type / flow profile
 */
function testSuite(
  this: Logger,
  options: { profile: string; target: string; title: string },
) {
  const version = readPackageVersion();
  const heading = `WCT v${version}  •  ${options.title}`;
  const targetLine = `Target   ${options.target}`;
  const profileLine = `Profile  ${options.profile}`;

  const innerWidth = Math.max(
    heading.length,
    targetLine.length,
    profileLine.length,
  );
  // Add 4 chars of padding (2 on each side)
  const boxWidth = innerWidth + 4;
  const top = `┌${"─".repeat(boxWidth)}┐`;
  const bottom = `└${"─".repeat(boxWidth)}┘`;
  const pad = (s: string) => `│  ${s.padEnd(innerWidth, " ")}  │`;

  process.stdout.write("\n");
  process.stdout.write(`${top}\n`);
  process.stdout.write(`${pad(heading)}\n`);
  process.stdout.write(`${pad(targetLine)}\n`);
  process.stdout.write(`${pad(profileLine)}\n`);
  process.stdout.write(`${bottom}\n`);
  process.stdout.write("\n");
}

/**
 * Creates a new logger instance with an additional tag.
 *
 * @param this The logger instance.
 * @param tag The tag to add.
 * @returns A new `Logger` instance with the added tag.
 */
function withTag(this: Logger, tag: string): Logger {
  const log = createConsola({
    ...this.options,
    defaults: {
      ...this.options?.defaults,
      tag: this.options?.defaults.tag
        ? this.options.defaults.tag + "|" + tag
        : tag,
    },
  });

  return Object.assign(log, {
    flowStep,
    nl,
    setLogOptions,
    testCompleted,
    testFailed,
    testSuite,
    withTag,
  });
}
