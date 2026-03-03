import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import {
  AuthorizeStepResponse,
  FetchMetadataStepResponse,
} from "@/step/issuance";
import { AttestationResponse } from "@/types";

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

  if (!authorizeResponse.response?.requestObject)
    throw new Error("Authorization Response not found");

  const redirectUri = authorizeResponse.response.requestObject.response_uri;

  if (!pushedAuthorizationRequestResponse.response)
    throw new Error(
      "Pushed Authorization Request Step did not return code_verifier",
    );

  const codeVerifier = pushedAuthorizationRequestResponse.response.codeVerifier;

  return {
    authorizationServer,
    code,
    codeVerifier,
    fetchMetadataResponse,
    redirectUri,
    walletAttestationResponse,
  };
}
