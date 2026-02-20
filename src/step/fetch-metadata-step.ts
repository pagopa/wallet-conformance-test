import { StepFlow, StepResponse } from "./step-flow";

export interface FetchMetadataExecuteResponse {
  discoveredVia?: "federation" | "oid4vci";
  entityStatementClaims?: any;
  headers?: Headers;
  status: number;
}

export interface FetchMetadataOptions {
  baseUrl: string;
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
  run(_: FetchMetadataOptions): Promise<FetchMetadataStepResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
