import { CryptoEngine, setEngine } from "pkijs";

let initialized = false;

/** Configures PKIjs to use the Node.js Web Crypto implementation (required for CMS). */
export function initPkijsCryptoEngine(): void {
  if (initialized) {
    return;
  }

  const webcrypto = globalThis.crypto;
  setEngine(
    "node",
    webcrypto,
    new CryptoEngine({
      crypto: webcrypto,
      name: "node",
      subtle: webcrypto.subtle,
    }),
  );
  initialized = true;
}
