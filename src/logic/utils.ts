import { readFileSync } from "node:fs";
import { parse } from "ini";

import { Logger } from "ts-log";

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

export async function fetchWithRetries(
	url: string | URL | Request,
	network: Config["network"],
	log: Logger,
	message: string = `Fetching data from ${url}`,
) {
	let retries = network.max_retries;

	log.info(message);

	let res: Response;
	try {
		res = await fetch(
			url,
			{
				method: "GET",
				headers: {
					"User-Agent": network.user_agent,
				},
				signal: AbortSignal.timeout(network.timeout * 1000)
			}
		);
	} catch (err: any) {
		if (err.name === "TimeoutError") {
			log.error(`Request timed out: aborting`);
			throw err;
		}

		if (retries-- <= 0) {
			log.error(`Request failed with no retries left: aborting`);
			throw err;
		}

		log.warn(`Request failed: ${retries} retries left`);
		res = await fetchWithRetries(
			url, 
			{
				...network,
				max_retries: retries
			},
			log,
			message
		);
	}

	log.info(`Request completed wih status ${res.status}`);
	
	return res;
}
