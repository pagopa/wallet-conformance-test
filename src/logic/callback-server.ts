import type { AuthorizationResponse } from "@pagopa/io-wallet-oid4vci";

import * as http from "node:http";
import { URL } from "node:url";

import { CALLBACK_PATH } from "./constants";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Starts a temporary HTTP server that listens for the OAuth2 authorization
 * callback on `http://localhost:{port}{CALLBACK_PATH}`.
 *
 * Resolves when the authorization server redirects the browser to the
 * callback endpoint with `code`, `iss`, and `state` query parameters.
 *
 * Rejects after `timeoutMs` milliseconds if no valid callback is received.
 */
export function startCallbackServer(
  port: number,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<AuthorizationResponse> {
  return new Promise<AuthorizationResponse>((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "", `http://localhost:${port}`);

      if (reqUrl.pathname !== CALLBACK_PATH) {
        res.writeHead(404).end("Not found");
        return;
      }

      const code = reqUrl.searchParams.get("code");
      const iss = reqUrl.searchParams.get("iss");
      const state = reqUrl.searchParams.get("state");

      if (!code || !iss || !state) {
        res
          .writeHead(400)
          .end(
            "Missing required parameters: code, iss, and state are all required.",
          );
        return;
      }

      res
        .writeHead(200, { "Content-Type": "text/html" })
        .end(
          "<html><body><h1>Authorization successful</h1><p>You can close this tab and return to the terminal.</p></body></html>",
        );

      cleanup();
      resolve({ code, iss, state });
    });

    const timer = setTimeout(() => {
      cleanup();
      reject(
        new Error(
          `Callback server timed out after ${timeoutMs / 1000}s waiting for authorization callback on port ${port}`,
        ),
      );
    }, timeoutMs);

    const cleanup = (): void => {
      clearTimeout(timer);
      server.close();
    };

    server.on("error", (err) => {
      cleanup();
      reject(
        new Error(`Callback server error on port ${port}: ${err.message}`),
      );
    });

    server.listen(port, "127.0.0.1");
  });
}
