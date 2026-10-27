import {
  type AuthorizationResponse,
  zAuthorizationResponse,
} from "@pagopa/io-wallet-oid4vci";

/** Parse the authorization response after URL query transport decoding. */
export const parseAuthorizationResponse = (
  searchParams: URLSearchParams,
): AuthorizationResponse => {
  const authorizationResponse = {
    code: searchParams.get("code"),
    iss: searchParams.get("iss"),
    state: searchParams.get("state"),
  };
  const missingParameters = Object.entries(authorizationResponse)
    .filter(([, value]) => !value)
    .map(([key]) => key);

  if (missingParameters.length > 0) {
    throw new Error(
      `Authorization redirect is missing parameter(s): ${missingParameters.join(", ")}`,
    );
  }

  const parsedAuthorizationResponse = zAuthorizationResponse.safeParse(
    authorizationResponse,
  );

  if (!parsedAuthorizationResponse.success) {
    throw new Error(
      `Invalid authorization response: ${parsedAuthorizationResponse.error.message}`,
    );
  }

  return parsedAuthorizationResponse.data;
};
