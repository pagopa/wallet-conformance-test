// -----------------------------------------------------------------------
// Helper: create a fresh popAttestation JWT (avoids 60 s TTL exhaustion)
// -----------------------------------------------------------------------

import { createClientAttestationPopJwt } from "@pagopa/io-wallet-oauth2";

import { partialCallbacks, signJwtCallback } from "@/logic";
import { AttestationResponse } from "@/types";

export async function createFreshPop(options: {
  authorizationServer: string;
  walletAttestationResponse: AttestationResponse;
}): Promise<string> {
  return createClientAttestationPopJwt({
    authorizationServer: options.authorizationServer,
    callbacks: {
      ...partialCallbacks,
      signJwt: signJwtCallback([
        options.walletAttestationResponse.unitKey.privateKey,
      ]),
    },
    clientAttestation: options.walletAttestationResponse.attestation,
  });
}
