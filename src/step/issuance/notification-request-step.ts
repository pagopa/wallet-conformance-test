import {
  createTokenDPoP,
  CreateTokenDPoPOptions,
} from "@pagopa/io-wallet-oauth2";

import { fetchWithConfig, partialCallbacks, signJwtCallback } from "@/logic";
import { KeyPair } from "@/types/key-pair";

import { StepFlow, StepResponse } from "../step-flow";

export type NotificationEvent =
  | "credential_accepted"
  | "credential_deleted"
  | "credential_failure";

export interface NotificationRequestExecuteResponse {
  event: NotificationEvent;
  status: number;
}

export type NotificationRequestResponse = StepResponse & {
  response?: NotificationRequestExecuteResponse;
};

export interface NotificationRequestStepOptions {
  accessToken: string;
  dPoPKey: KeyPair;
  event: NotificationEvent;
  notificationEndpoint: string;
  notificationId: string;
}

/**
 * Flow step to notify the issuer's notification endpoint of a credential event.
 * Uses the access token and DPoP key from the Token Request step.
 * Only HTTP 204 is considered success.
 */
export class NotificationRequestDefaultStep extends StepFlow {
  static readonly tag = "NOTIFICATION_REQUEST";

  async run(
    options: NotificationRequestStepOptions,
  ): Promise<NotificationRequestResponse> {
    const log = this.log;

    log.debug("Starting Notification Request Step");

    return this.execute<NotificationRequestExecuteResponse>(async () => {
      log.info("Generating DPoP for Notification Request...");
      const dpop = await this.buildDPoP(options);

      log.info(
        `Sending Notification Request to ${options.notificationEndpoint}`,
      );
      log.debug(
        "Notification Request body:",
        JSON.stringify({
          event: options.event,
          notification_id: options.notificationId,
        }),
      );

      const fetch = fetchWithConfig(this.config.network);
      const httpResponse = await fetch(options.notificationEndpoint, {
        body: JSON.stringify({
          event: options.event,
          notification_id: options.notificationId,
        }),
        headers: {
          Authorization: `DPoP ${options.accessToken}`,
          "Content-Type": "application/json",
          DPoP: dpop,
        },
        method: "POST",
      });

      const { status } = httpResponse;
      log.debug(`Notification Response status: ${status}`);

      if (status !== 204) {
        let errorBody: unknown = null;
        try {
          errorBody = await httpResponse.json();
          log.debug("Notification endpoint error response body:", errorBody);
        } catch {
          // non-JSON body — swallow silently
        }

        throw new Error(
          `Notification Endpoint returned unexpected status ${status}. Expected 204 No Content.${errorBody ? ` Response body: ${JSON.stringify(errorBody)}` : ""}`,
        );
      }

      return { event: options.event, status };
    });
  }

  tag(): string {
    return NotificationRequestDefaultStep.tag;
  }

  private async buildDPoP(
    options: NotificationRequestStepOptions,
  ): Promise<string> {
    const { dPoPKey } = options;

    const dpopOptions: CreateTokenDPoPOptions = {
      accessToken: options.accessToken,
      callbacks: {
        ...partialCallbacks,
        signJwt: signJwtCallback([dPoPKey.privateKey]),
      },
      jti: crypto.randomUUID(),
      signer: {
        alg: "ES256",
        method: "jwk",
        publicJwk: dPoPKey.publicKey,
      },
      tokenRequest: {
        method: "POST",
        url: options.notificationEndpoint,
      },
    };

    const { jwt } = await createTokenDPoP(dpopOptions);
    return jwt;
  }
}
