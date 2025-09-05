import { writeFileSync } from "node:fs";

import type { Jwk, JwtSigner } from "@openid4vc/oauth2";
import { decodeJwt, JWK, generateKeyPair } from "jose";
import KSUID from "ksuid";

import { KeyPair } from "@/types";

/**
 * Generates an ES256 key pair and saves it to a file.
 *
 * @param fileName The name of the file to save the key pair to.
 * @returns A promise that resolves to the generated key pair.
 */
export async function generateKey(
	fileName: string
): Promise<KeyPair> {
	const keyPair = await generateKeyPair("ES256", { extractable: true });

	const {
		oth: _,
		...priv
	} = await crypto.subtle.exportKey(
		"jwk",
		keyPair.privateKey
	);
	const {
		oth: __,
		...pub
	} = await crypto.subtle.exportKey(
		"jwk",
		keyPair.publicKey
	);
	
	const kid = KSUID.randomSync().string;
	const exportedPair: KeyPair = {
		privateKey: {
			kid: kid,
			...priv
		},
		publicKey: {
			kid: kid,
			...pub
		}
	};
	writeFileSync(
		fileName,
		JSON.stringify(exportedPair)
	);

	return exportedPair;
}

/**
 * Extracts a JWK from a trust chain.
 *
 * @param trustChains An array of trust chains.
 * @param signerKid The kid of the signer's JWK.
 * @returns The JWK extracted from the trust chain.
 * @throws An error if the trust chain is empty or the key is not found.
 */
function jwkFromTrustChain(trustChains: string[], signerKid: string): Jwk {
	if (trustChains.length < 1) throw new Error("empty trust chain");
	// TODO check if trust chain is valid
	const claims = decodeJwt(trustChains[0]!) as { jwks: { keys: Jwk[] } };
	console.log(trustChains[0])
	const federationJwk = claims.jwks.keys.find(
		(key: Jwk) => key.kid === signerKid,
	);

	if (!federationJwk) throw new Error("key not found in trust chain");

	return federationJwk;
}

/**
 * Extracts a JWK from a signer.
 *
 * @param signer The signer object.
 * @returns The extracted JWK.
 * @throws An error if the signer method is not supported.
 */
export function jwkFromSigner(signer: JwtSigner): JWK {
	let jwk: Jwk;
	if (signer.method === "did") {		
		const didUrl = signer.didUrl.split("#")[0];

		if (!didUrl) throw new Error("missing did JWT");
		jwk = JSON.parse(
			Buffer.from(
				didUrl.replace("did:jwk:", ""),
				"base64url"
			).toString()
		);
	} else if (signer.method === "jwk")
		jwk = signer.publicJwk;
	else if (signer.method as string === "federation") {
		const {
			trustChain: trustChain,
			kid: kid
		} = signer as { trustChain: string[], kid: string};
		if (trustChain.length > 0)
			jwk = jwkFromTrustChain(trustChain, kid);
		else
			throw new Error("trust chain not found");
	} else
		throw new Error("signer method not supported");

	return jwk as JWK;
}