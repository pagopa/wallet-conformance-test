import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import {
  type AuthorizationRequestObject,
  type CreateAuthorizationResponseResult,
  type Openid4vpAuthorizationRequestHeader,
  type ParsedQrCode,
} from "@pagopa/io-wallet-oid4vp";

import type { AttestationResponse, KeyPairJwk } from "@/types";

import { StepFlow, type StepResponse } from "@/step/step-flow";

export interface AuthorizationRequestExecuteStepResponse {
  authorizationRequestHeader: Openid4vpAuthorizationRequestHeader;
  authorizationResponse: CreateAuthorizationResponseResult;
  parsedQrCode: ParsedQrCode;
  requestObject: AuthorizationRequestObject;
  responseUri: string;
}

export interface AuthorizationRequestOptions {
  /**
   * Credentials along with their associated DPoP keys.
   */
  credentials: CredentialWithKey[];

  /**
   * Metadata about the verifier from the wallet's perspective.
   */
  verifierMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Attestation response from the wallet.
   */
  walletAttestation: AttestationResponse;
}

export type AuthorizationRequestStepResponse = StepResponse & {
  response?: AuthorizationRequestExecuteStepResponse;
};

export interface CredentialWithKey {
  credential: string;
  dpopJwk: KeyPairJwk;
}

/**
 * Implementation of the Authorization Request Step for OpenID4VP flow.
 * This step handles fetching the authorization request, building the VP token,
 * and creating the authorization response to be sent back to the verifier.
 */
export class AuthorizationRequestDefaultStep extends StepFlow {
  tag = "AUTHORIZATION";

  async run(
    _: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResponse> {
    this.log.warn("Method not implemented.");
    return { success: false };
  }
}
