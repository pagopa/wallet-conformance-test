import {
  ConsolaOptions,
  ConsolaReporter,
  createConsola,
  LogObject,
} from "consola";
import { openSync, writeFileSync } from "node:fs";

import { Logger } from "@/types";

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

function newLogger(options?: Partial<ConsolaOptions>): Logger {
  return Object.assign(createConsola({ ...options, fancy: true }), {
    nl,
    setLogOptions,
    testCompleted,
    testFailed,
    withTag,
  });
}

function nl() {
  process.stdout.write("\n");
}

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

function testCompleted(this: Logger, success = true) {
  if (success) {
    this.info("Test completed ✅");
  } else {
    this.error("Test completed ❌");
  }
  this.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

function testFailed(this: Logger) {
  this.error("Test failed ❌");
}

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
    nl,
    setLogOptions,
    testCompleted,
    testFailed,
    withTag,
  });
}
