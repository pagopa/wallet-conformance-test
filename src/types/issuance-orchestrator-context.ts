import {
  AuthorizeStepResponse,
  CredentialRequestResponse,
  DeferredCredentialRequestResponse,
  FetchMetadataStepResponse,
  NonceRequestResponse,
  NotificationRequestResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";

import { AttestationResponse } from "./attestation-response";
import { CredentialWithKey } from "./credential";
import { KeyPair } from "./key-pair";

export interface DeferredIssuanceFlowResponse {
  deferredCredentialResponse?: DeferredCredentialRequestResponse;
  error?: Error;
  fetchMetadataResponse?: FetchMetadataStepResponse;
  success: boolean;
  tokenResponse?: TokenRequestResponse;
  walletAttestationResponse?: AttestationResponse;
}

export interface IssuanceFlowResponse {
  authorizeResponse?: AuthorizeStepResponse;
  credentialResponse?: CredentialRequestResponse;
  error?: Error;
  fetchMetadataResponse?: FetchMetadataStepResponse;
  nonceResponse?: NonceRequestResponse;
  notificationRequestResponse?: NotificationRequestResponse;
  pushedAuthorizationRequestResponse?: PushedAuthorizationRequestResponse;
  success: boolean;
  tokenResponse?: TokenRequestResponse;
  walletAttestationResponse?: AttestationResponse;
}

export interface ReissuanceFlowResponse {
  credentialResponse?: CredentialRequestResponse;
  error?: Error;
  fetchMetadataResponse?: FetchMetadataStepResponse;
  nonceResponse?: NonceRequestResponse;
  refreshedCredential?: CredentialWithKey;
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

export interface RunThroughRefreshTokenContext {
  credentialIssuer: string;
  dPoPKey: KeyPair;
  fetchMetadataResponse: FetchMetadataStepResponse;
  tokenResponse: TokenRequestResponse;
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
