import { FetchMetadataStepResponse } from "@/step";
import {
  AuthorizeStepResponse,
  PushedAuthorizationRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";
import { AttestationResponse } from "./attestation-response";

export interface RunThroughParContext {
  fetchMetadataResponse: FetchMetadataStepResponse;
  popAttestation: string;
  pushedAuthorizationRequestEndpoint: string;
  pushedAuthorizationRequestResponse: PushedAuthorizationRequestResponse;
  walletAttestationResponse: AttestationResponse;
}

export type RunThroughAuthorizeContext = RunThroughParContext & {
  authorizeResponse: AuthorizeStepResponse;
};

export type RunThroughTokenContext = RunThroughAuthorizeContext & {
  tokenResponse: TokenRequestResponse;
};
