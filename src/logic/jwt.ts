import type {
	Jwk,
	SignJwtCallback,
	VerifyJwtCallback
} from "@openid4vc/oauth2";
import { type JsonWebKey } from '@openid-federation/core';
import { type JWK, importJWK, SignJWT, jwtVerify } from "jose";

import { jwkFromSigner } from "./jwk";

/**
 * Creates a callback function for signing JWTs.
 *
 * @param privateJwks An array of private JSON Web Keys.
 * @returns A callback function that can be used to sign JWTs.
 */
export function signJwtCallback(privateJwks: JWK[]): SignJwtCallback {
	return async (signer, { header, payload }) => {
		const publicJwk = jwkFromSigner(signer);
		const privateJwk = privateJwks
			.find(jwkPrv => jwkPrv.kid === publicJwk.kid);

		if (!privateJwk)
			throw new Error(
				`No private key available for \n${JSON.stringify(publicJwk)}`,
			);

		const key = await importJWK(privateJwk as JWK, signer.alg);

		return {
			jwt: await new SignJWT(payload).setProtectedHeader(header).sign(key),
			signerJwk: publicJwk as Jwk,
		};
	};
}

/**
 * Verifies a JWT with the signer's public key.
 *
 * @param signer The JWT signer.
 * @param jwt The JWT to verify.
 * @returns A promise that resolves to an object containing the verification result.
 */
export const verifyJwt: VerifyJwtCallback = async (signer, jwt) => {
	const publicJwk = jwkFromSigner(signer);
	const key = await importJWK(publicJwk as JWK, signer.alg);
	
	try {
		await jwtVerify(jwt.compact, key);

		return {
			signerJwk: publicJwk as Jwk,
			verified: true,
		};
	} catch(e) {
		return {
			verified: false,
		};
	}
}
