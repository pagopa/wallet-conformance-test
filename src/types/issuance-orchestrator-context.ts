import { FetchMetadataStepResponse } from "@/step/issuance";
import {
  AuthorizeStepResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";

import { AttestationResponse } from "./attestation-response";
import { KeyPair } from "./key-pair";

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
