import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { decodeJwt } from "jose";

import { fetchWithRetries } from "@/logic/utils";

import { StepFlow, StepResponse } from "../step-flow";

export interface FetchMetadataVpExecuteResponse {
  entityStatementClaims?: any;
  headers?: Headers;
  status: number;
}

export interface FetchMetadataVpOptions {
  baseUrl: string;
}

export type FetchMetadataVpStepResponse = StepResponse & {
  response?: FetchMetadataVpExecuteResponse;
};

export class FetchMetadataVpDefaultStep extends StepFlow {
  tag = "FETCH METADATA";

  async run(options: FetchMetadataVpOptions): Promise<FetchMetadataVpStepResponse> {
    const log = this.log.withTag(this.tag);
    const url = `${options.baseUrl}/.well-known/openid-federation`;

    log.info("Discovering metadata...");
    log.info(`Fetching Relying Party metadata from ${url}`);

    return this.execute<FetchMetadataVpExecuteResponse>(async () => {
      const res = await fetchWithRetries(url, this.config.network);
      log.info(
        `Request completed with status ${res.response.status} after ${res.attempts} failed attempts`,
      );
      const entityStatementJwt = await res.response.text();

      log.info("Parsing entity statement JWT...");

      let entityStatementJwtDecoded;
      try {
        entityStatementJwtDecoded = decodeJwt(entityStatementJwt);
        log.debug("Decoded entity statement JWT:", JSON.stringify(entityStatementJwtDecoded));
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
        headers: res.response.headers,
        status: res.response.status,
      };
    });
  }
}
