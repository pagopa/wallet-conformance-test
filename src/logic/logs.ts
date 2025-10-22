import {
  ConsolaInstance,
  ConsolaReporter,
  createConsola,
  LogObject,
} from "consola";
import { openSync, writeFileSync } from "node:fs";

import { Logger } from "@/types/Logger";

export function createLogger(): Logger {
  const log = createConsola({
    fancy: true,
    formatOptions: {
      colors: true,
      columns: 20,
      date: false,
    },
    level: 3,
  });

  return Object.assign(log, { setLogOptions: setLogOptionsCallback });
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

function setLogOptionsCallback(
  this: ConsolaInstance,
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
        .replace(/%\(levelname\)/, logObj.type.toUpperCase())
        .replace(/%\(message\)/, logObj.args.join(" ") ?? "");

    reporters.push({
      log: (logObj) => {
        console.log(formatLog(logObj));
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
