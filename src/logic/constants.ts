/** @deprecated Use {@link getCallbackRedirectUri} with a config-driven port instead. */
export const REDIRECT_URI = "https://client.example.org/cb";

export const CALLBACK_PATH = "/cb";

/**
 * Returns the local redirect URI used by the OAuth2 authorization callback
 * server. Must match the `redirect_uri` registered in the PAR step and used
 * in the token request.
 */
export const getCallbackRedirectUri = (port: number): string =>
  `http://localhost:${port}${CALLBACK_PATH}`;
