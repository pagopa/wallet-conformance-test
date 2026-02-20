import { fetchWithRetries } from "@/logic";
import { StepResponse } from "@/step";
import { NonceRequestDefaultStep } from "@/step/issuance/nonce-request-step";

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

export class NonceRequestITWallet1_0Step extends NonceRequestDefaultStep {
  tag = "NONCE_REQUEST";

  async run(options: NonceRequestStepOptions): Promise<NonceRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Nonce Request Step`);

    return this.execute<NonceRequestExecuteResponse>(async () => {
      log.info("Fetching Nonce from", options.nonceEndpoint);
      const fetchNonce = await fetchWithRetries(
        options.nonceEndpoint,
        this.config.network,
        {
          method: "POST",
        },
      );

      return {
        attempts: fetchNonce.attempts,
        cacheControl: fetchNonce.response.headers.get("Cache-Control"),
        contentType: fetchNonce.response.headers.get("Content-Type"),
        nonce: await fetchNonce.response.json(),
      };
    });
  }
}
