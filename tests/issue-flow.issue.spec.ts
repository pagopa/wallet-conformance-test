import { describe, expect, test } from "vitest";

import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { decodeJwt } from "jose";

import { loadConfig } from "@/logic";

describe(
	"Issue Flow Test",
	/**
	 * Tests the metadata discovery process by fetching the entity statement
	 * from the issuer's well-known endpoint. It ensures that the response is valid
	 * and conforms to the expected schema.
	 */
	() => test("Metadata Discovery", async () => {
		const config = loadConfig("./config.ini");

		let retries = config.network.max_retries
		const metadataRequest = () => fetch(
			`${config.issuance.url}/.well-known/openid-federation`,
			{
				method: "GET",
				headers: {
					"User-Agent": config.network.user_agent,
				},
				signal: AbortSignal.timeout(config.network.timeout * 1e3)
			}
		).catch((err): Promise<Response> => {
			if (retries-- <= 0 || err.name === "TimeoutError")
				throw err;

			return metadataRequest();
		});

		const metadata = await metadataRequest();
		expect(metadata.status).toBe(200);

		const parsedData = itWalletEntityStatementClaimsSchema
			.parse(decodeJwt(await metadata.text()));
		expect(parsedData).not.toBeUndefined();
		console.log(JSON.stringify(parsedData, null, 4));
	})
);
