import { writeFileSync } from "node:fs";

import {
	type JsonWebKey,
	type JsonWebKeySet,
	jsonWebKeySchema
} from '@openid-federation/core';
import type { JwtSigner } from "@openid4vc/oauth2";
import KSUID from "ksuid";

import { KeyPair } from "@/types";
import { exportJWK, generateKeyPair } from "jose";

/**
 * Generates a new cryptographic key pair (ECDSA with P-256 curve),
 * saves it to a file, and returns the key pair.
 *
 * @param fileName The name of the file to save the key pair to.
 * @returns A promise that resolves to the generated key pair.
 */
export async function generateKey(
	fileName: string
): Promise<KeyPair> {
	const keyPair = await generateKeyPair(
		"ES256",
		{
			crv: "P-256",
			extractable: true
		}
	);
	const priv = await exportJWK(keyPair.privateKey);
	const pub = await exportJWK(keyPair.publicKey);
	
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
 * Extracts a JWK from a trust chain array based on the signer's KID.
 *
 * @param trustChains An array of JWTs representing the trust chain.
 * @param signerKid The KID of the signer to look for in the trust chain.
 * @returns The JWK found in the trust chain.
 * @throws An error if the trust chain is empty or the key is not found.
 */
function jwkFromTrustChain(
	trustChains: string[],
	signerKid: string
): JsonWebKey {
	if (trustChains.length < 1) throw new Error("empty trust chain");
	// TODO check if trust chain is valid
	const [ _, payload, __ ] = trustChains[0]!.split(".");
	
	if (!payload) throw new TypeError("malformed jwt in trust chain");
	
	const claims = JSON.parse(
		Buffer.from(payload, "base64url").toString()
	) as {jwks: JsonWebKeySet};
	const federationJwk = claims.jwks.keys.find(
		(key: JsonWebKey) => key.kid === signerKid,
	);

	if (!federationJwk) throw new Error("key not found in trust chain");

	return federationJwk;
}

/**
 * Extracts a public JWK from a JWT signer.
 *
 * @param signer The JWT signer.
 * @returns The extracted public JWK.
 * @throws An error if the signer method is not supported.
 */
export function jwkFromSigner(signer: JwtSigner): JsonWebKey {
	let jwk: JsonWebKey;
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
		jwk = jsonWebKeySchema.parse(signer.publicJwk);
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

	return jwk;
}
