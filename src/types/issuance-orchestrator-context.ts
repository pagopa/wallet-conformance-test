import { FetchMetadataStepResponse } from "@/step";
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
  fetchMetadataResponse: FetchMetadataStepResponse;
  popAttestation: string;
  pushedAuthorizationRequestEndpoint: string;
  pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
  walletAttestationResponse: AttestationResponse;
}

export type RunThroughTokenContext = RunThroughAuthorizeContext & {
  tokenResponse: TokenRequestResponse;
};
