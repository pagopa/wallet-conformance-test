import {
  fetchAndValidateTrustChain,
  itWalletEntityStatementClaimsSchema,
} from "@pagopa/io-wallet-oid-federation";
import { createFetcher, parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { decodeJwt } from "jose";

import {
  fetchWithConfig,
  fetchWithRetries,
  partialCallbacks,
} from "@/logic/utils";
import { recordSessionEntityNameFromEntityConfiguration } from "@/report/session-runtime";

import { StepFlow, StepResponse } from "../step-flow";

export interface FetchMetadataVpExecuteResponse {
  // Entity statement metadata is version-dependent and consumed structurally by orchestrators/tests.
  entityStatementClaims?: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

export interface FetchMetadataVpOptions {
  baseUrl: string;
}

export type FetchMetadataVpStepResponse = StepResponse & {
  response?: FetchMetadataVpExecuteResponse;
};

export class FetchMetadataVpDefaultStep extends StepFlow {
  static readonly tag = "FETCH_METADATA_VP";

  async retrieveEntityStatementJwt(url: URL) {
    const isVerifyEnabled = this.config.trust_anchor.verify;
    if (isVerifyEnabled) {
      const resValidateTrustChain = await fetchAndValidateTrustChain(url.href, {
        callbacks: {
          ...partialCallbacks,
          fetch: createFetcher(fetchWithConfig(this.config.network)),
        },
        trustAnchorUrls: this.config.trust.federation_trust_anchors as [
          string,
          ...string[],
        ],
      });
      return resValidateTrustChain[0];
    }

    // Skip validation trust chain, just fetch metadata
    const wellKnownUrl = `${url.href}/.well-known/openid-federation`;
    const response = await fetchWithRetries(wellKnownUrl, this.config.network);
    return await response.response.text();
  }

  async run(
    options: FetchMetadataVpOptions,
  ): Promise<FetchMetadataVpStepResponse> {
    const log = this.log;
    const url = new URL(options.baseUrl);

    log.info("Discovering metadata...");
    log.info(`Fetching Relying Party metadata from ${url}`);

    return this.execute<FetchMetadataVpExecuteResponse>(async () => {
      const entityStatementJwt = await this.retrieveEntityStatementJwt(url);

      if (!entityStatementJwt) {
        throw new Error(
          "Error in trust chain evaluation, neither the base jwt has been fetched",
        );
      }

      log.info("Parsing entity statement JWT...");

      let entityStatementJwtDecoded;
      try {
        entityStatementJwtDecoded = decodeJwt(entityStatementJwt);
        log.debug(
          "Decoded entity statement JWT:",
          JSON.stringify(entityStatementJwtDecoded),
        );
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

      recordSessionEntityNameFromEntityConfiguration(
        "presentation",
        entityStatementClaims,
      );

      return {
        entityStatementClaims,
      };
    });
  }

  tag(): string {
    return FetchMetadataVpDefaultStep.tag;
  }
}
