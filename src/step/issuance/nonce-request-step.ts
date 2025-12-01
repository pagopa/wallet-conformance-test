import { fetchWithRetries } from "@/logic";
import { StepFlow, StepResult } from "@/step";

export interface NonceRequestExecuteResponse {
  attempts: number;
  cacheControl: null | string;
  contentType: null | string;
  nonce: object;
}

export type NonceRequestResponse = StepResult & {
  response?: NonceRequestExecuteResponse;
};

export interface NonceRequestStepOptions {
  nonceEndpoint: string;
}

export class TokenRequestDefaultStep extends StepFlow {
  tag = "NONCE_REQUEST";

  async run(options: NonceRequestStepOptions): Promise<NonceRequestResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Token Request Step`);

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
