import { readFileSync } from "node:fs";
import { parse } from "ini";

import { Config } from "@/types";

/**
 * Loads and parses the configuration from a specified INI file.
 *
 * @param fileName The path to the INI configuration file.
 * @returns The parsed configuration object.
 */
export function loadConfig(fileName: string): Config {
	const textConfig = readFileSync(fileName, "utf-8");

	return parse(textConfig) as Config;
}
