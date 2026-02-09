import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { decodeJwt } from "jose";

import { fetchWithRetries } from "@/logic";
import {
  FetchMetadataDefaultStep,
  FetchMetadataExecuteResponse,
  FetchMetadataStepResponse,
} from "@/step/fetch-metadata-step";

/**
 * Integration test step to fetch metadata from the issuer's well-known endpoint and parse the entity statement JWT.
 * This step is designed to follow the IT Wallet 1.0 specification for metadata fetching.
 *
 * The step performs the following actions:
 * 1. Constructs the URL for the well-known endpoint based on the issuer's base URL from the configuration.
 * 2. Fetches the metadata from the well-known endpoint, with retries according to the network configuration.
 * 3. Logs the HTTP status and headers of the response.
 * 4. Attempts to decode the entity statement JWT from the response body.
 * 5. Parses the claims from the decoded JWT using the IT Wallet entity statement claims schema.
 *
 * The response of this step includes:
 * - status: HTTP status code of the response.
 * - headers: HTTP headers of the response.
 * - entityStatementJwt: The raw entity statement JWT as a string (if decoding was successful).
 * - entityStatementClaims: The parsed claims from the entity statement JWT (if parsing was successful).
 */
export class FetchMetadataITWallet1_0Step extends FetchMetadataDefaultStep {
  tag = "FETCH METADATA";

  async run(): Promise<FetchMetadataStepResponse> {
    const log = this.log.withTag(this.tag);
    const url = `${this.prepareBaseUrl()}/.well-known/openid-federation`;

    log.info("Discovering metadata...");
    log.info(`Fetching metadata from ${url}`);

    return this.execute<FetchMetadataExecuteResponse>(async () => {
      const res = await fetchWithRetries(url, this.config.network);
      log.info(
        `Request completed with status ${res.response.status} after ${res.attempts} failed attempts`,
      );
      const entityStatementJwt = await res.response.text();

      log.info("Parsing entity statement JWT...");

      let entityStatementJwtDecoded;
      try {
        entityStatementJwtDecoded = decodeJwt(entityStatementJwt);
        log.debug("Decoded entity statement JWT:", entityStatementJwtDecoded);
      } catch (e) {
        log.info("Failed to decode entity statement JWT:", e);
      }

      let entityStatementClaims;
      try {
        const schema = itWalletEntityStatementClaimsSchema;
        entityStatementClaims = parseWithErrorHandling(
          schema,
          entityStatementJwtDecoded,
        );
      } catch (e) {
        entityStatementClaims = entityStatementJwtDecoded;
        log.info("Failed to parse entity statement claims:", e);
      }

      return {
        entityStatementClaims,
        entityStatementJwt,
        headers: res.response.headers,
        status: res.response.status,
      };
    });
  }

  private prepareBaseUrl(): string {
    if (!this.config.presentation.verifier) {
      const authorizeUrl = new URL(
        this.config.presentation.authorize_request_url,
      );
      const clientId = authorizeUrl.searchParams.get("client_id");

      if (!clientId) {
        throw new Error(
          "client_id parameter not found in authorize_request_url and verifier not configured",
        );
      }

      const baseUrl = new URL(clientId);
      this.log.info(
        `Using client_id from authorize_request_url as verifier baseUrl: ${baseUrl.href}`,
      );
      return baseUrl.href;
    }

    return this.config.presentation.verifier;
  }
}
