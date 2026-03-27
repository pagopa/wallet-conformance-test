import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  FetchMetadataStepResponse,
  NonceRequestResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";

import { AttestationResponse } from "./attestation-response";
import { KeyPair } from "./key-pair";

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
  /**
   * Ephemeral DPoP key pair generated during the Token Request.
   * This key is reused for the DPoP proof in the Credential Request.
   */
  dPoPKey: KeyPair;
  tokenResponse: TokenRequestResponse;
};
