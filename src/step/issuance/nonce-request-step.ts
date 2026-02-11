import { StepFlow, StepResult } from "@/step";

export interface NonceRequestExecuteResponse {
  attempts: number;
  cacheControl: null | string;
  contentType: null | string;
  nonce: NonceResponsePayload;
}

export type NonceRequestResponse = StepResult & {
  response?: NonceRequestExecuteResponse;
};

export interface NonceRequestStepOptions {
  nonceEndpoint: string;
}

export type NonceResponsePayload = Record<string, unknown>;

/**
 * Flow step to request a nonce from the issuer's nonce endpoint.
 * The nonce is typically used in subsequent requests to ensure freshness and prevent replay attacks.
 */
export class NonceRequestDefaultStep extends StepFlow {
  tag = "NONCE_REQUEST";

  async run(_: NonceRequestStepOptions): Promise<NonceRequestResponse> {
    this.log.warn("Method not implemented.");
    return Promise.resolve({ success: false });
  }
}
