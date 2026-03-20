import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  FetchMetadataStepResponse,
  NonceRequestResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";

import { AttestationResponse } from "./attestation-response";

export interface IssuanceFlowResponse {
  authorizeResponse?: AuthorizeStepResponse;
  credentialResponse?: CredentialRequestResponse;
  error?: Error;
  fetchMetadataResponse?: FetchMetadataStepResponse;
  nonceResponse?: NonceRequestResponse;
  pushedAuthorizationRequestResponse?: PushedAuthorizationRequestResponse;
  success: boolean;
  tokenResponse?: TokenRequestResponse;
  walletAttestationResponse?: AttestationResponse;
}

export type RunThroughAuthorizeContext = RunThroughParContext & {
  authorizationEndpoint: string;
  authorizeResponse: AuthorizeStepResponse;
};

export interface RunThroughParContext {
  authorizationServer: string;
  credentialIssuer: string;
  fetchMetadataResponse: FetchMetadataStepResponse;
  popAttestation: string;
  pushedAuthorizationRequestEndpoint: string;
  pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
  walletAttestationResponse: AttestationResponse;
}

export type RunThroughTokenContext = RunThroughAuthorizeContext & {
  tokenResponse: TokenRequestResponse;
};
