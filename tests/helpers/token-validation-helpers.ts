import { decodeJwt, JWTPayload } from "jose";

import { getCallbackRedirectUri } from "@/logic/constants";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeStepResponse,
  FetchMetadataStepResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";

/**
 * Decodes a JWT and throws a descriptive error (including the offending token)
 * if decoding fails, so malformed tokens fail the test instead of propagating
 * an opaque `jose` parsing error.
 */
export function decodeJwtOrThrow<T extends JWTPayload = JWTPayload>(
  token: string,
  label = "token",
): T {
  try {
    return decodeJwt(token) as T;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid ${label}: ${token} (${reason})`);
  }
}

export async function runAndValidateAuthorize(
  orchestrator: WalletIssuanceOrchestratorFlow,
): Promise<{
  authorizationServer: string;
  code: string;
  codeVerifier: string;
  fetchMetadataResponse: FetchMetadataStepResponse;
  redirectUri: string;
  walletAttestationResponse: AttestationResponse;
}> {
  const ctx = await orchestrator.runThroughAuthorize();
  const authorizeResponse: AuthorizeStepResponse = ctx.authorizeResponse;

  const walletAttestationResponse = ctx.walletAttestationResponse;
  const authorizationServer = ctx.authorizationServer;
  const fetchMetadataResponse = ctx.fetchMetadataResponse;
  const pushedAuthorizationRequestResponse =
    ctx.pushedAuthorizationRequestResponse;

  if (!authorizeResponse.response?.authorizeResponse)
    throw new Error("Authorization Response not found");

  const code = authorizeResponse.response.authorizeResponse.code;

  if (!pushedAuthorizationRequestResponse.response)
    throw new Error(
      "Pushed Authorization Request Step did not return code_verifier",
    );

  const codeVerifier = pushedAuthorizationRequestResponse.response.codeVerifier;

  const config = orchestrator.getConfig();

  return {
    authorizationServer,
    code,
    codeVerifier,
    fetchMetadataResponse,
    redirectUri: getCallbackRedirectUri(config.issuance.callback_port),
    walletAttestationResponse,
  };
}
