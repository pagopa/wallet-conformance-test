import { StepFlow, StepResult } from "./step-flow";

export interface FetchMetadataExecuteResponse {
  entityStatementClaims?: any;
  headers?: Headers;
  status: number;
  discoveredVia?: "federation" | "oid4vci";
}

export interface FetchMetadataOptions {
  baseUrl: string;
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
  tag = "FetchMetadata";
  run(_: FetchMetadataOptions): Promise<FetchMetadataStepResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
