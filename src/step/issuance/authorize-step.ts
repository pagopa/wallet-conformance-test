import { fetchWithRetries } from "@/logic";

import { StepFlow, StepResult } from "../step-flow";

export interface AuthorizeExecuteResponse {
  code: string;
  headers: Headers;
  status: number;
}

export interface AuthorizeStepOptions {
  /**
   * Authorization Endpoint URL
   */
  authorizationEndpoint: string;

  /**
   * Client ID of the OAuth2 Client
   *
   * */
  clientId: string;

  /**
   * Request URI obtained from the Pushed Authorization Request step
   */
  requestUri: string;
}

export type AuthorizeStepResponse = StepResult & {
  response?: AuthorizeExecuteResponse;
};

export class AuthorizeDefaultStep extends StepFlow {
  tag = "AUTHORIZE";

  async run(options: AuthorizeStepOptions): Promise<AuthorizeStepResponse> {
    const log = this.log.withTag(this.tag);

    log.info(`Starting Authorize Step`);

    return this.execute<AuthorizeExecuteResponse>(async () => {
      log.info(
        `Fetching Authorize information from ${options.authorizationEndpoint}`,
      );
      const fetchAuthorize = await fetchWithRetries(
        `${options.authorizationEndpoint}?client_id=${options.clientId}&request_uri=${options.requestUri}`,
        this.config.network,
        { redirect: "manual" },
      );
      const location = fetchAuthorize.response.headers.get("location");
      if (!location) {
        log.error("Missing 'location' parameter in authorize request redirect");
        throw new Error(
          "Missing 'location' parameter in authorize request redirect",
        );
      }

      const code = new URL(location).searchParams.get("code");
      if (!code) {
        log.error("Missing 'code' parameter in authorize request response");
        throw new Error(
          "Missing 'code' parameter in authorize request response",
        );
      }

      return {
        code,
        headers: fetchAuthorize.response.headers,
        status: fetchAuthorize.response.status,
      };
    });
  }
}
