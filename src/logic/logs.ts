import { openSync, writeFileSync } from "node:fs";

import { Logger } from "@/types/Logger";
import {
	ConsolaInstance,
	createConsola,
	ConsolaReporter,
	LogObject
} from "consola";

export function createLogger(): Logger {
	const log = createConsola({
		level: 3,
		fancy: true,
		formatOptions: {
			columns: 20,
			colors: true,
			date: false
		}
	});

	return Object.assign(log, { setLogOptions: setLogOptionsCallback });
}

function levelCode(level: string): number {
	switch (level.toLowerCase()) {
	case "debug":
		return 5;
	case "trace":
		return 4;
	case "error":
		return 2;
	case "fatal":
		return 1;
	case "silent":
		return 0;
	case "info":
	default:
		return 3;
	}
}

function setLogOptionsCallback(
	this: ConsolaInstance,
	options: { level?: string, format?: string, path?: string }
) {
	const reporters: ConsolaReporter[] = [];
	let formatLog = (
		logObj: LogObject
	): string => logObj.message ?? "";

	this.level = levelCode(options.level ?? "fatal");

	if (options.format) {
		const format = options.format;
		formatLog = (logObj: LogObject): string => {
			return format
				.replace(/%\(utc\)/, logObj.date.toUTCString())
				.replace(/%\(date\)/, logObj.date.toISOString())
				.replace(/%\(tag\)/, logObj.tag)
				.replace(/%\(levelname\)/, logObj.type.toUpperCase())
				.replace(/%\(message\)/, logObj.args.join(" ") ?? "");
		};

		reporters.push({
			log: (logObj) => {
				console.log(formatLog(logObj))
			}
		})
	}
	
	if (options.path) try {
		const file = openSync(options.path, "w");
		reporters.push({
			log: (logObj) => {
				writeFileSync(file, `${formatLog(logObj)}\n`);
			}
		});
	} catch (e) {
		this.warn(`Unable to write logs to file ${options.path}`);
	}

	if (reporters.length > 0)
		this.setReporters(reporters)
}
