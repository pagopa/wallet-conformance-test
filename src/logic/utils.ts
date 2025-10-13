import { Openid4vciWalletProviderOptions } from "@openid4vc/openid4vci";
import { JWK } from "jose";

import { signJwtCallback, verifyJwt } from ".";

const callbacks: Record<string, Openid4vciWalletProviderOptions> = {};

export const getCallbacks = (key: JWK): Openid4vciWalletProviderOptions => {
  if (!key.kid)
    throw new TypeError(`missing required field "kid" in object ${key}`);

  if (!callbacks[key.kid])
    callbacks[key.kid] = {
      callbacks: {
        fetch,
        generateRandom: crypto.getRandomValues,
        hash: (data: ArrayBuffer, alg: string) =>
          crypto.subtle.digest(alg, data),
        signJwt: signJwtCallback([key]),
        verifyJwt,
      },
    };

  return callbacks[key.kid];
};
