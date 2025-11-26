import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { decodeJwt } from "jose";
import { Schema } from "zod";

import { fetchWithRetries } from "@/logic/utils";
import { StepFlow, StepResult } from "@/step/step-flow";

export interface FetchMetadataExecuteResponse {
  entityStatementClaims?: any;
  entityStatementJwt?: string;
  headers: Headers;
  status: number;
}

export interface FetchMetadataOptions {
  /**
   * Base URL of the issuer or verifier to fetch metadata from.
   */
  baseUrl: string;
  /**
   * Schema to validate the entity statement claims against.
   * If not provided, @itWalletEntityStatementClaimsSchema is used.
   */
  entityStatementClaimsSchema?: Schema;

  /**
   * Overrides the default well-known path /.well-known/openid-federation for fetching metadata.
   */
  wellKnownPath?: string;
}

export type FetchMetadataStepResponse = StepResult & {
  response?: FetchMetadataExecuteResponse;
};

/**
 * Flow step to fetch issuer or verifier metadata from the well-known endpoint.
 * It retrieves the entity statement JWT and its claims.
 * Base URI is taken from the configuration.
 *
 * If HTTP response is executed successfully, the response field contains:
 * - status: HTTP status code of the response.
 * - headers: HTTP headers of the response.
 *
 * If the entity statement JWT is successfully decoded as JWT, the response field also contains:
 * - entityStatementJwt: The raw entity statement JWT as a string.
 *
 * If the entity statement claims are successfully parsed, the response field also contains:
 * - entityStatementClaims: The parsed claims from the entity statement JWT.
 */
export class FetchMetadataDefaultStep extends StepFlow {
  tag = "FETCH METADATA";

  async run(options: FetchMetadataOptions): Promise<FetchMetadataStepResponse> {
    const log = this.log.withTag(this.tag);
    const url = `${options.baseUrl}${options.wellKnownPath}`;

    log.debug("Fetch Metadata Options: ", JSON.stringify(options));
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
        const schema =
          options.entityStatementClaimsSchema ??
          itWalletEntityStatementClaimsSchema;
        entityStatementClaims = parseWithErrorHandling(
          schema,
          entityStatementJwtDecoded,
        );
      } catch (e) {
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
}
