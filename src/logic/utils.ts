import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { createHash, randomBytes } from "node:crypto";

import { verifyJwt } from ".";

export const partialCallbacks: Partial<CallbackContext> = {
  fetch,
  generateRandom: (bytes) => randomBytes(bytes),
  hash: (data, alg) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};
