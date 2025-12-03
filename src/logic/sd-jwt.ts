import { KeyPair } from "@/types";
import { importJWK, SignJWT } from "jose";

/**
 * Creates a VP Token SD-JWT by combining the provided SD-JWT with a Key Binding JWT (KB-JWT).
 * @param param0 
 * @returns 
 */
export async function createVpTokenSdJwt({
  sdJwt,
  dpopJwk,
  nonce,
  sd_hash,
  client_id,
}: {
  sdJwt: string;
  dpopJwk: KeyPair["privateKey"];
  nonce: string;
  sd_hash: string;
  client_id: string;
}): Promise<string> { 

    // Use dpop key for the key binding JWT (wallet holder's key)
    const dpopPrivateKey = await importJWK(dpopJwk, "ES256");
    const kbJwt = await new SignJWT({
        nonce,
        sd_hash,
    })
    .setProtectedHeader({
        alg: "ES256",
        typ: "kb+jwt",
    })
    .setAudience(client_id)
    .setIssuedAt()
    .sign(dpopPrivateKey);

    // <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>

    return sdJwt.endsWith('~') ? `${sdJwt}${kbJwt}` : `${sdJwt}~${kbJwt}`;   
}