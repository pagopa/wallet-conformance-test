import { describe, expect, test } from "vitest";

import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { decodeJwt } from "jose";

import { fetchWithRetries, loadConfig } from "@/logic";
import { Log } from "@/types/Logger";

describe(
	"Issue Flow Test",
	/**
	 * Tests the metadata discovery process by fetching the entity statement
	 * from the issuer's well-known endpoint. It ensures that the response is valid
	 * and conforms to the expected schema.
	 */
	() => {
		const log = new Log();
		log.info("Setting Up Wallet conformance Tests");

		log.info("Loading Configuration...");
		const config = loadConfig("./config.ini");
		log.info("Configuration Loaded", {
			issuanceUrl: config.issuance.url,
			credentialsDir: config.wallet.credentials_storage_path,
			maxRetries: config.network.max_retries,
			timeout: `${config.network.timeout}s`,
			userAgent: config.network.user_agent,
		});

		test("Metadata Discovery", async () => {
			log.info("ISS-003 Discovery test started");
			const metadataUrl = `${config.issuance.url}/.well-known/openid-federation`;

			log.info("Discoverying issuer's metadata...");
			const metadata = await fetchWithRetries(
				metadataUrl,
				config.network,
				log,
				`Fetching metadata from ${metadataUrl}`
			);

			log.info("Asserting response status...");
			expect(metadata.status).toBe(200);

			log.info("Checking non empty response body...");
			const data = await metadata.text();
			expect(data).not.toBeUndefined();

			log.info("Parsing response body as JWT...");
			const decodedData = decodeJwt(data);

			try {
				log.info("Validating response format...")
				const parsedData = itWalletEntityStatementClaimsSchema
					.parse(decodedData);

				log.info(`Obtained response: ${JSON.stringify(parsedData, null, 4)}`);
				log.info("ISS-003 Discovery test completed ✅");
			} catch(err: any) {
				if (err.name === "ZodError") {
					log.error("❌ Schema validation failed", err.errors);
				} else {
					log.error("❌ Unexpected error during parsing", { error: err.message });
				}
				
				log.error("ISS-003 Discovery test failed ❌");

				throw err;
			}
		});
	}
);
