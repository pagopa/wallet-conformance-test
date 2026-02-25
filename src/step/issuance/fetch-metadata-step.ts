import { fetchMetadata } from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { partialCallbacks } from "@/logic/utils";

import { StepFlow, StepResponse } from "../step-flow";

export interface FetchMetadataExecuteResponse {
  discoveredVia?: "federation" | "oid4vci";
  entityStatementClaims?: any;
  status: number;
}

export interface FetchMetadataOptions {
  baseUrl: string;

  /**
   * Configuration for the io-wallet-sdk to be used for metadata discovery.
   */
  ioWalletSdkConfig: IoWalletSdkConfig<ItWalletSpecsVersion>;
}

export type FetchMetadataStepResponse = StepResponse & {
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
 * - discoveredVia: The discovery method used (e.g. "federation" or "oid4vci").
 *
 * If the entity statement claims are successfully parsed, the response field also contains:
 * - entityStatementClaims: The parsed claims from the entity statement JWT.
 */
export class FetchMetadataDefaultStep extends StepFlow {
  tag = "FetchMetadata";
  async run(options: FetchMetadataOptions): Promise<FetchMetadataStepResponse> {
    const log = this.log.withTag(this.tag);

    log.info("Discovering metadata...");

    return this.execute<FetchMetadataExecuteResponse>(async () => {
      const result = await fetchMetadata({
        callbacks: {
          fetch: partialCallbacks.fetch,
        },
        config: options.ioWalletSdkConfig,
        credentialIssuerUrl: options.baseUrl,
      });

      return {
        discoveredVia: result.discoveredVia,
        entityStatementClaims: result.openid_federation_claims,
        status: 200,
      };
    });
  }
}
