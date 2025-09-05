import type {
	Jwk,
	SignJwtCallback,
	VerifyJwtCallback
} from "@openid4vc/oauth2";
import { JWK, SignJWT, importJWK, jwtVerify } from "jose";

import { jwkFromSigner } from "./jwk";

/**
 * Returns a callback function for signing a JWT.
 *
 * @param privateJwks An array of private JWKs.
 * @returns A callback function that takes a signer and a JWT and returns a signed JWT.
 */
export function signJwtCallback(privateJwks: JWK[]): SignJwtCallback {
	const callback: SignJwtCallback = async (signer, jwt) => {
		const publicJwk = jwkFromSigner(signer);

		const privateJwk = privateJwks.find(jwkPrv => jwkPrv.kid === publicJwk.kid);
		if (!privateJwk)
			throw new Error(
				`No private key available for \n${JSON.stringify(publicJwk)}`,
			);

		const privateKey = await importJWK(privateJwk, signer.alg);

		return {
			jwt: await new SignJWT(jwt.payload)
				.setProtectedHeader({ ...jwt.header, alg: signer.alg })
				.sign(privateKey),
			signerJwk: publicJwk as Jwk,
		};
	};

	return callback;
}

/**
 * Verifies a JWT.
 *
 * @param signer The signer of the JWT.
 * @param jwt The JWT to verify.
 * @returns An object with a boolean indicating if the JWT is verified and the signer's JWK.
 */
export const verifyJwt: VerifyJwtCallback = async (signer, jwt) => {
	const publicJwk = jwkFromSigner(signer);
	const publicKey = await importJWK(publicJwk, signer.alg);

	try {
	    await jwtVerify(jwt.compact, publicKey, {
			currentDate: jwt.payload.exp
				? new Date((jwt.payload.exp - 300) * 1000)
				: undefined,
	    });

		return {
			signerJwk: publicJwk as Jwk,
			verified: true,
		};
	} catch {
		return {
			verified: false,
		};
	}
}