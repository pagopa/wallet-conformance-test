import { PushedAuthorizationResponse } from "@pagopa/io-wallet-oauth2";
import {
  createPushedAuthorizationRequest,
  CreatePushedAuthorizationRequestOptions,
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
} from "@pagopa/io-wallet-oauth2";

import { fetchWithConfig, partialCallbacks, signJwtCallback } from "@/logic";
import { REDIRECT_URI } from "@/logic/constants";
import { StepFlow, StepResponse } from "@/step";
import { AttestationResponse } from "@/types";
import { PID_CREDENTIAL_CONFIGURATION_ID } from "@/types/pid-issuance";

/**
 * Single `authorization_details` entry as accepted by the SDK PAR builder.
 * Derived from {@link CreatePushedAuthorizationRequestOptions} so it stays in
 * sync with the SDK schema without importing a non-exported type.
 */
export type AuthorizationDetail = NonNullable<
  CreatePushedAuthorizationRequestOptions["authorization_details"]
>[number];

export type PushedAuthorizationRequestExecuteResponse =
  PushedAuthorizationResponse & {
    /**
     * Code verifier used in the Pushed Authorization Request, if not provided it will be generated internally
     */
    codeVerifier: string;
  };

export type PushedAuthorizationRequestResponse = StepResponse & {
  response?: PushedAuthorizationRequestExecuteResponse;
};

export interface PushedAuthorizationRequestStepOptions {
  /**
   * Issuer Base URL
   */
  baseUrl: string;

  /**
   * Client ID of the OAuth2 Client, it will be loaded from the wallet attestation public key kid
   */
  clientId: string;

  /**
   * Code verifier used in the Pushed Authorization Request, if not provided it will be generated internally
   */
  codeVerifier?: string;

  /**
   * Optional overrides for CreatePushedAuthorizationRequestOptions.
   * When provided, these values will be spread over the computed defaults,
   * allowing tests to override any PAR parameter (e.g. clientId, audience, redirectUri).
   */
  createParOverrides?: Partial<CreatePushedAuthorizationRequestOptions>;

  /**
   * Credential Configuration ID for the requested credential
   */
  credentialConfigurationIds: string[];

  /**
   * DPoP JWT used to authenticate the client, it will be created using the wallet attestation
   */
  popAttestation: string;

  /**
   * Pushed Authorization Request Endpoint URL, it will be loaded from the issuer metadata
   */
  pushedAuthorizationRequestEndpoint: string;

  /**
   * Wallet Attestation used to authenticate the client, it will be loaded from the configuration
   */
  walletAttestation: Omit<AttestationResponse, "created">;
}

/**
 * Flow step to send a pushed authorization request to the issuer's pushed authorization request endpoint.
 * It uses the wallet attestation to authenticate the client and requests a credential using the specified
 * credential configuration ID.
 *
 * The response of this step includes the pushed authorization response containing the request URI and other details.
 */
export class PushedAuthorizationRequestDefaultStep extends StepFlow {
  static readonly tag = "PUSHED_AUTHORIZATION_REQUEST";

  async run(
    options: PushedAuthorizationRequestStepOptions,
  ): Promise<PushedAuthorizationRequestResponse> {
    return await this.execute<PushedAuthorizationRequestExecuteResponse>(
      async () => {
        const log = this.log;

        log.debug(`Starting PushedAuthorizationRequest Step`);

        const { unitKey } = options.walletAttestation;

        const callbacks = {
          ...partialCallbacks,
          fetch: fetchWithConfig(this.config.network),
          signJwt: signJwtCallback([unitKey.privateKey]),
        };

        // B1-6.3: the PID detail is owned exclusively by the overridable hook
        // (B1-6.2), so it is filtered out of the generic map and re-added from
        // the hook. This keeps a single PID entry and makes withPidPar() (B1-6.5)
        // fully authoritative over it. When mode = none the hook returns [],
        // leaving the standard (Q)EAA flow byte-for-byte unchanged.
        const authorizationDetails: AuthorizationDetail[] = [
          ...options.credentialConfigurationIds
            .filter((id) => id !== PID_CREDENTIAL_CONFIGURATION_ID)
            .map((id) => ({
              credential_configuration_id: id,
              type: "openid_credential" as const,
            })),
          ...this.pidCredentialAuthorizationDetails(),
        ];

        const createParOptions = {
          audience: options.baseUrl,
          authorization_details: authorizationDetails,
          // Hardcode require_signed_request_object to true as the wallet is expected to always sign the request object
          // We'll need to allow overriding this in case we want to test unsigned request objects in negative test cases
          authorizationServerMetadata: {
            require_signed_request_object: true,
          },
          callbacks:
            callbacks as CreatePushedAuthorizationRequestOptions["callbacks"],
          clientId: unitKey.publicKey.kid,
          codeChallengeMethodsSupported: ["S256"],
          config: this.ioWalletSdkConfig,
          dpop: {
            signer: {
              alg: "ES256",
              method: "jwk",
              publicJwk: unitKey.publicKey,
            },
          },
          pkceCodeVerifier: options.codeVerifier,
          redirectUri: REDIRECT_URI,
          responseMode: "query",
        };

        const finalParOptions = {
          ...createParOptions,
          ...options.createParOverrides,
        } as CreatePushedAuthorizationRequestOptions;

        log.debug(
          "Final PAR options:",
          JSON.stringify(finalParOptions, null, 2),
        );

        log.info(
          `Sending PAR request to ${options.pushedAuthorizationRequestEndpoint}`,
        );
        log.debug(
          `PAR request credentialConfigurationId: ${options.credentialConfigurationIds}`,
        );
        const pushedAuthorizationRequest =
          await createPushedAuthorizationRequest(finalParOptions);

        const codeVerifier = pushedAuthorizationRequest.pkceCodeVerifier;

        const fetchOptions: fetchPushedAuthorizationResponseOptions = {
          callbacks: callbacks,
          clientAttestationDPoP: options.popAttestation,
          pushedAuthorizationRequest,
          pushedAuthorizationRequestEndpoint:
            options.pushedAuthorizationRequestEndpoint,
          walletAttestation: options.walletAttestation.attestation,
        };

        log.info(
          `Fetching PAR response from ${options.pushedAuthorizationRequestEndpoint}`,
        );

        log.debug(`PKCE code verifier ${codeVerifier}`);

        const parResponse =
          await fetchPushedAuthorizationResponse(fetchOptions);
        log.debug("PAR response:", JSON.stringify(parResponse, null, 2));

        return {
          ...parResponse,
          codeVerifier,
        };
      },
    );
  }

  tag(): string {
    return PushedAuthorizationRequestDefaultStep.tag;
  }

  /**
   * B1-6.4: optional `it_l2+document_proof` authorization detail for the L2+
   * MRTD flow, gated behind `[issuance_pid].document_proof_enabled` (default
   * off, post REQ-00). Returns `undefined` unless `mode = l2plus` and the flag
   * with its required fields are set.
   *
   * Uses the SDK (`io-wallet-oauth2@1.4.1`) field names `challenge_method` /
   * `challenge_redirect_uri`. The current online spec names these
   * `multi_step_method` / `multi_step_redirect_uri`; reconcile via an SDK
   * upgrade once the target PID Provider's spec version is confirmed (B1-6.1).
   */
  protected documentProofAuthorizationDetail():
    | AuthorizationDetail
    | undefined {
    const issuancePid = this.config.issuance_pid;
    if (
      issuancePid?.mode !== "l2plus" ||
      !issuancePid.document_proof_enabled ||
      !issuancePid.document_proof_redirect_uri ||
      !issuancePid.document_proof_idphinting
    ) {
      return undefined;
    }

    return {
      challenge_method: "mrtd+ias",
      challenge_redirect_uri: issuancePid.document_proof_redirect_uri,
      idphinting: issuancePid.document_proof_idphinting,
      type: "it_l2+document_proof",
    };
  }

  /**
   * B1-6.2 (FR-10): overridable hook returning the extra `authorization_details`
   * entries required by the PID issuance flow.
   *
   * - `mode = none` (or `[issuance_pid]` absent) → `[]`, so the standard
   *   (Q)EAA flow is unaffected.
   * - `mode = l2plus | l3` → a PID detail for
   *   `dc_sd_jwt_PersonIdentificationData`.
   * - `mode = l2plus` with `document_proof_enabled` → additionally an
   *   `it_l2+document_proof` detail (B1-6.4).
   *
   * Override via `withPidPar()` (B1-6.5) for negative tests.
   */
  protected pidCredentialAuthorizationDetails(): AuthorizationDetail[] {
    const issuancePid = this.config.issuance_pid;
    const mode = issuancePid?.mode ?? "none";
    if (mode === "none") {
      return [];
    }

    const details: AuthorizationDetail[] = [
      {
        credential_configuration_id: PID_CREDENTIAL_CONFIGURATION_ID,
        type: "openid_credential",
      },
    ];

    const documentProof = this.documentProofAuthorizationDetail();
    if (documentProof) {
      details.push(documentProof);
    }

    return details;
  }
}
