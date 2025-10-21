import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { BinaryLike, createHash, randomBytes } from "node:crypto";

import { verifyJwt } from ".";

export const partialCallbacks: Partial<CallbackContext> = {
  fetch,
  generateRandom: randomBytes,
  hash: (data: BinaryLike, alg: string) =>
    createHash(alg.replace("-", "").toLowerCase()).update(data).digest(),
  verifyJwt,
};
