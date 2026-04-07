import type { AuthorizationRequestStepResponse } from "@/step/presentation";
import type { FetchMetadataVpStepResponse } from "@/step/presentation";
import type { RedirectUriStepResponse } from "@/step/presentation";

export interface PresentationFlowResponse {
  authorizationRequestResult?: AuthorizationRequestStepResponse;
  error?: Error;
  fetchMetadataResult?: FetchMetadataVpStepResponse;
  redirectUriResult?: RedirectUriStepResponse;
  success: boolean;
}
