import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import type {
  AuthorizationRequestStepResponse,
  FetchMetadataVpStepResponse,
  RedirectUriStepResponse,
} from "@/step/presentation";

import { AttestationResponse } from "./attestation-response";
import { CredentialWithKey } from "./credential";

export interface PresentationFlowResponse {
  authorizationRequestResponse?: AuthorizationRequestStepResponse;
  error?: Error;
  fetchMetadataResponse?: FetchMetadataVpStepResponse;
  redirectUriResponse?: RedirectUriStepResponse;
  success: boolean;
}

export interface RunThroughAuthorizeVpContext {
  authorizationRequestResponse: AuthorizationRequestStepResponse;
  credentials: CredentialWithKey[];
  fetchMetadataResponse?: FetchMetadataVpStepResponse;
  verifierMetadata?: ItWalletCredentialVerifierMetadata;
  walletAttestationResponse: AttestationResponse;
}
