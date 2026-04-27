import type { AuthorizationRequestStepResponse } from "@/step/presentation";
import type { FetchMetadataVpStepResponse } from "@/step/presentation";
import type { RedirectUriStepResponse } from "@/step/presentation";

import { AttestationResponse } from "./attestation-response";
import { CredentialWithKey } from "./credential";

export interface PresentationFlowResponse {
  authorizationRequestResponse?: AuthorizationRequestStepResponse;
  error?: Error;
  fetchMetadataResponse?: FetchMetadataVpStepResponse;
  redirectUriResponse?: RedirectUriStepResponse;
  success: boolean;
}

export interface RunThroughAuthorizeContext {
  authorizationRequestResponse: AuthorizationRequestStepResponse;
  credentials: CredentialWithKey[];
  fetchMetadataResponse: FetchMetadataVpStepResponse;
  verifierMetadata: any;
  walletAttestationResponse: AttestationResponse;
}
