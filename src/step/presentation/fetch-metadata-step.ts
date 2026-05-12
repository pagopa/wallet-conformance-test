import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import {
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
  jwtVerify,
} from "jose";

import { fetchWithConfig, fetchWithRetries } from "@/logic/utils";

import { StepFlow, StepResponse } from "../step-flow";
import { fetchMetadata } from "@pagopa/io-wallet-oid4vci";
import { createVerifyJwt } from "@/logic";

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

  async run(
    options: FetchMetadataVpOptions,
  ): Promise<FetchMetadataVpStepResponse> {
    const log = this.log.withTag(this.tag);
    const url = `${options.baseUrl}/.well-known/openid-federation`;

    log.info("Discovering metadata...");
    log.info(`Fetching Relying Party metadata from ${url}`);

    return this.execute<FetchMetadataVpExecuteResponse>(async () => {
      const result = await fetchMetadata({
        callbacks: {
          fetch: fetchWithConfig(this.config.network),
          verifyJwt: createVerifyJwt(
            this.config.trust.federation_trust_anchors,
          ),
        },
        config: this.ioWalletSdkConfig,
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
