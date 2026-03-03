import { FetchMetadataStepResponse } from "@/step/issuance";
import {
  AuthorizeStepResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";

import { AttestationResponse } from "./attestation-response";

export type RunThroughAuthorizeContext = RunThroughParContext & {
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
