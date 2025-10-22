import { ValidationError } from "@openid4vc/utils";
import {
  itWalletEntityStatementClaimsSchema,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-oid-federation";
import { decodeJwt } from "jose";
import { describe, expect, test } from "vitest";

import { createLogger, fetchWithRetries, loadConfig } from "@/logic";

describe("Issue Flow Test" /**
 * Tests the metadata discovery process by fetching the entity statement
 * from the issuer's well-known endpoint. It ensures that the response is valid
 * and conforms to the expected schema.
 */, async () => {
  const baseLog = createLogger();
  const setupLog = baseLog.withTag("SETUP");

  setupLog.info("Setting Up Wallet conformance Tests");
  setupLog.info("Loading Configuration...");
  const config = loadConfig("./config.ini");

  baseLog.setLogOptions({
    format: config.logging.log_format,
    level: config.logging.log_level,
    path: config.logging.log_file,
  });

  setupLog.info("Configuration Loaded:\n", {
    credentialsDir: config.wallet.credentials_storage_path,
    issuanceUrl: config.issuance.url,
    maxRetries: config.network.max_retries,
    timeout: `${config.network.timeout}s`,
    userAgent: config.network.user_agent,
  });

  test("ISS-003: Metadata Discovery should return valid entity metadata statement", async () => {
    const log = baseLog.withTag("ISS-003");

    log.start("ISS-003 Discovery test started");
    const metadataUrl = `${config.issuance.url}/.well-known/openid-federation`;

    log.info("Discoverying issuer's metadata...");
    log.info(`Fetching metadata from ${metadataUrl}`);
    const res = await fetchWithRetries(metadataUrl, config.network);
    log.info(
      `Request completed wih status ${res.response.status} after ${res.attempts} attempts`,
    );
    const metadata = res.response;

    log.info("Asserting response status...");
    expect(metadata.status).toBe(200);

    log.info("Checking non empty response body...");
    const data = await metadata.text();
    expect(data).not.toBeUndefined();

    log.info("Parsing response body as JWT...");
    const decodedData = decodeJwt(data);
    log.debug(decodedData);

    try {
      log.info("Validating response format...");
      parseWithErrorHandling(
        itWalletEntityStatementClaimsSchema,
        decodedData,
        "Error validating metadata",
      );

      log.info(`Response matches the required format`);
      log.success("ISS-003 Discovery test completed ✅");
    } catch (e) {
      if (e instanceof ValidationError) {
        log.error("Schema validation failed");
        expect
          .soft(
            e.message.replace(": ", ":\n\t").replace(/,([A-Za-z])/g, "\n\t$1"),
          )
          .toBeNull();
      } else {
        log.error("Unexpected error during parsing");
        expect.soft(e).toBeNull();
      }

      log.error("ISS-003 Discovery test failed");
    }
  });
});
