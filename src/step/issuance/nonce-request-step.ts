import { fetchWithRetries } from "@/logic";
import { StepFlow } from "@/step";
import { StepResponse } from "@/step";

export interface NonceRequestExecuteResponse {
  attempts: number;
  cacheControl: null | string;
  contentType: null | string;
  nonce: NonceResponsePayload;
}

export type NonceRequestResponse = StepResponse & {
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
  static readonly tag = "NONCE_REQUEST";

  async run(options: NonceRequestStepOptions): Promise<NonceRequestResponse> {
    const log = this.log;

    log.debug(`Starting Nonce Request Step`);

    return this.execute<NonceRequestExecuteResponse>(async () => {
      log.info("Fetching Nonce from", options.nonceEndpoint);
      const fetchNonce = await fetchWithRetries(
        options.nonceEndpoint,
        this.config.network,
        {
          // OpenID4VCI: POST with empty body and no Content-Type.
          body: undefined,
          headers: {
            "Content-Length": "0",
          },
          method: "POST",
        },
      );

      if (!fetchNonce.response.ok) {
        const body = await fetchNonce.response.text();
        throw new Error(
          `Nonce endpoint returned HTTP ${fetchNonce.response.status}: ${body}`,
        );
      }

      const nonce = (await fetchNonce.response.json()) as NonceResponsePayload;
      if (typeof nonce.c_nonce !== "string" || nonce.c_nonce.length === 0) {
        throw new Error(
          `Nonce response missing c_nonce: ${JSON.stringify(nonce)}`,
        );
      }

      return {
        attempts: fetchNonce.attempts,
        cacheControl: fetchNonce.response.headers.get("Cache-Control"),
        contentType: fetchNonce.response.headers.get("Content-Type"),
        nonce,
      };
    });
  }

  tag(): string {
    return NonceRequestDefaultStep.tag;
  }
}
