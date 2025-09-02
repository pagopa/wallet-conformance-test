import { readFileSync, writeFileSync } from "node:fs";

import type {
	Jwk,
	SignJwtCallback
} from "@openid4vc/oauth2";
import {
	ItWalletProvider,
	WalletAttestationOptions
} from "@pagopa/io-wallet-oid4vci";

import type { Config } from "@/types";

function trustChainToJwk(trustChains: string[], signerKid: string): Jwk {
	if (trustChains.length < 1) throw new Error("empty trust chain");
	// TODO check if trust chain is valid
	return jwkToEntityConf(trustChains[0]!, signerKid);
}

function jwkToEntityConf(jwk: string, signerKid: string): Jwk {
	const claims = fromJwt(jwk);
	const federationJwk = (claims.jwks as { keys: Jwk[] }).keys.find(
		(key: Jwk) => key.kid === signerKid,
	);
	if (!federationJwk) {
		throw new Error("Key not found in trust chain");
	}
	// Convert x5c to array if it's a string, need to adapt to jose
	const transformedJwk = {
		...federationJwk,
		...(federationJwk.x5c
			? {
				x5c: federationJwk.x5c
					? Array.isArray(federationJwk.x5c)
						? federationJwk.x5c
						: [federationJwk.x5c]
					: undefined,
			} : {}
		),
	};
	return transformedJwk as Jwk;
}

function signJwt(privateJwks: Jwk[]): SignJwtCallback {
	return async (
		signer: { [key: string]: unknown },
		jwt: {
			header: { [key: string]: unknown },
			payload: { [key: string]: unknown }
		}
	): Promise<{ jwt: string, signerJwk: Jwk }> => {
		let jwk: Jwk;
		if (signer.method === "did") {
			const didUrl = (signer.didUrl ?? "") as string;
			if (didUrl.length === 0) throw new Error("missing did JWT");

			jwk = JSON.parse(
				Buffer.from(
					didUrl.split("#")[0]?.replace("did:jwk:", "")!,
					"base64url"
				).toString()
			);
		} else if (signer.method === "jwk")
			jwk = signer.publicJwk as Jwk;
		else if (signer.method === "federation") {
			const trustChain = (signer.trustChain ?? []) as string[]
			if (trustChain && trustChain.length > 0)
				jwk = trustChainToJwk(trustChain, signer.kid as string);
			else
				throw new Error("Trust chain not found");
		} else
			throw new Error("Signer method not supported");

		const privateJwk = privateJwks.find(jwkPrv => jwkPrv.kid === jwk.kid);
		if (!privateJwk)
			throw new Error(
				`No private key available for \n${JSON.stringify(jwk)}`,
			);

		return {
			jwt: await toJwt(
				jwt.header,
				jwt.payload,
				privateJwk as JsonWebKey
			),
			signerJwk: jwk as Jwk,
		};
	};
}

async function verifyJwt(
	signer: { [key: string]: unknown },
	jwt: {
		compact: string,
		payload: { [key: string]: unknown }
	}
): Promise<{ signerJwk?: Jwk, verified: boolean }> {
	let jwk: Jwk;
	if (signer.method === "did") {
		const didUrl = (signer.didUrl ?? "") as string;
		if (didUrl.length === 0) throw new Error("missing did JWT");

		jwk = JSON.parse(
			Buffer.from(
				didUrl.split("#")[0]?.replace("did:jwk:", "")!,
				"base64url"
			).toString()
		);
	} else if (signer.method === "jwk")
		jwk = signer.publicJwk as Jwk;
	else if (signer.method === "federation") {
		const trustChain = (signer.trustChain ?? []) as string[]
		if (trustChain && trustChain.length > 0)
			jwk = trustChainToJwk(trustChain, signer.kid as string);
		else
			throw new Error("Trust chain not found");
	} else
		throw new Error("Verifier method not supported");

	const alg = signer.alg as string;
	const publicKey = await crypto.subtle.importKey(
		"jwk", jwk as JsonWebKey, {
			name: jwk.alg!,
			namedCurve: jwk.crv!,
		},
		true, ["verify"]
	);
	
	try {
		const [ header, body, signature ] = jwt.compact.split(".")
		await crypto.subtle.verify(
			alg,
			publicKey,
			Buffer.from(signature!),
			Buffer.from(`${header}.${body}`)
		);

		return {
			signerJwk: jwk,
			verified: true,
		};
	} catch {
		return {
			verified: false,
		};
	}
}

async function generateKey(
	fileName: string
): Promise<CryptoKeyPair> {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "ECDSA",
			namedCurve: "P-256"
		},
		true,
		["sign", "verify"]
	).catch((err) => { throw err; });

	const priv = await crypto.subtle.exportKey(
		"jwk",
		keyPair.privateKey
	);
	writeFileSync(
		fileName,
		JSON.stringify(priv)
	);

	const pub = await crypto.subtle.exportKey(
		"jwk",
		keyPair.publicKey
	);
	writeFileSync(
		`${fileName}.pub`,
		JSON.stringify(pub)
	);

	return keyPair;
}

export async function loadAttestation(
	wallet: Config["wallet"]
): Promise<string> {
	const attestationPath = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_id}`;
	let attestation: string;

	try {
		attestation = readFileSync(attestationPath, "utf-8");
	} catch {
		console.info("missing wallet attestation: generating a new one");

		const providerKeyPair = await generateKey(
			`${wallet.backup_storage_path}/wallet_provider_jwks`
		);
		const providerJwkPriv = {
			kid: "kzouDFz7NlhG_cW00MX_e5bfmGmMRCH4UOxzy16TqJY",
			...(await crypto.subtle.exportKey(
				"jwk", providerKeyPair.privateKey,
			))
		};
		const providerJwkPub = {
			kid: "kzouDFz7NlhG_cW00MX_e5bfmGmMRCH4UOxzy16TqJY",
			...(await crypto.subtle.exportKey(
				"jwk", providerKeyPair.publicKey,
			))
		}

		const unitKeyPair = await generateKey(
			`${wallet.backup_storage_path}/wallet_unit_jwks`
		);
		const unitJwkPub = {
			kid: "unit-key",
			...(await crypto.subtle.exportKey(
				"jwk", unitKeyPair.publicKey,
			))
		}

		const attestationOptions: WalletAttestationOptions = {
			issuer: wallet.wallet_provider_base_url,
			signer: {
				walletProviderJwkPublicKid: providerJwkPub.kid,
				trustChain: ["eyJraWQiOiJISDlKWTl4RkEzZUJwN0d2UXNKRWZ2Z1lYekh2NGRFZThsbmt4dDB2MGNRIiwidHlwIjoiZW50aXR5LXN0YXRlbWVudCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdXRob3JpdHlfaGludHMiOltdLCJpc3MiOiJodHRwczovL3dhbGxldC1wcm92aWRlci5jb20iLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJrem91REZ6N05saEdfY1cwME1YX2U1YmZtR21NUkNINFVPeHp5MTZUcUpZIiwieCI6IjNLWlJidmdaVER0Nk5nQWJnOHpISnRqUVM2RkhENldlT0VDN1liSS1aNTQiLCJ5IjoiNU5TSFVhWWJVMjV0WHE3bUpwQ29YVUZtaU41Ykt1ZU9fNlBNc1E0cnBTSSIsImFsZyI6IkVTMjU2In1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiaG9tZXBhZ2VfdXJpIjoiaHR0cHM6Ly9pby5pdGFsaWEuaXQiLCJsb2dvX3VyaSI6Imh0dHBzOi8vaW8uaXRhbGlhLml0L2Fzc2V0cy9pbWcvaW8taXQtbG9nby1ibHVlLnN2ZyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiUGFnb1BhIFMucC5BLiIsInBvbGljeV91cmkiOiJodHRwczovL2lvLml0YWxpYS5pdC9wcml2YWN5LXBvbGljeSIsInRvc191cmkiOiJodHRwczovL2lvLml0YWxpYS5pdC9wcml2YWN5LXBvbGljeSJ9LCJ3YWxsZXRfcHJvdmlkZXIiOnsiYWFsX3ZhbHVlc19zdXBwb3J0ZWQiOlsiaHR0cHM6Ly9pby1kLWl0bi1ldWRpdy1hcGktZnVuYy0wMS5henVyZXdlYnNpdGVzLm5ldC9Mb0EvYmFzaWMiLCJodHRwczovL2lvLWQtaXRuLWV1ZGl3LWFwaS1mdW5jLTAxLmF6dXJld2Vic2l0ZXMubmV0L0xvQS9tZWRpdW0iLCJodHRwczovL2lvLWQtaXRuLWV1ZGl3LWFwaS1mdW5jLTAxLmF6dXJld2Vic2l0ZXMubmV0L0xvQS9oaWdodCJdLCJncmFudF90eXBlc19zdXBwb3J0ZWQiOlsidXJuOmlldGY6cGFyYW1zOm9hdXRoOmNsaWVudC1hc3NlcnRpb24tdHlwZTpqd3QtY2xpZW50LWF0dGVzdGF0aW9uIl0sImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJ4IjoiM0taUmJ2Z1pURHQ2TmdBYmc4ekhKdGpRUzZGSEQ2V2VPRUM3WWJJLVo1NCIsInkiOiI1TlNIVWFZYlUyNXRYcTdtSnBDb1hVRm1pTjViS3VlT182UE1zUTRycFNJIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJrem91REZ6N05saEdfY1cwME1YX2U1YmZtR21NUkNINFVPeHp5MTZUcUpZIn1dfSwidG9rZW5fZW5kcG9pbnQiOiJodHRwczovL2lvLWQtaXRuLWV1ZGl3LWFwaS1mdW5jLTAxLmF6dXJld2Vic2l0ZXMubmV0L3Rva2VuIiwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJwcml2YXRlX2tleV9qd3QiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19LCJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaGFpcDovLyIsInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJ2cF90b2tlbiJdLCJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXX19LCJjbGllbnRfaWRfc2NoZW1lc19zdXBwb3J0ZWQiOlsicHJlLXJlZ2lzdHJlZCIsIng1MDlfc2FuX2RucyJdfSwic3ViIjoiaHR0cHM6Ly93YWxsZXQtcHJvdmlkZXIuY29tIiwiaWF0IjoxNzQ3ODM4Nzc4LCJleHAiOjE3NDc5MjUxNzh9.bTMo-_ADJDgMPtIiCgv2EAWRGStOzkkQx_p8TFua4c0Enud6kDwP5vkVnWwCDa-0bm4YgTeqpswrMNrN1KmvwQ"]
			},
			dpopJwkPublic: {
				kty: unitJwkPub.kty ?? "",
				...unitJwkPub
			} as any,
			walletName: wallet.wallet_name
			// walletLink: `${wallet.wallet_provider_base_url}/wallet`
		}

		const callbacks = {
			clientAuthentication: () => {},
			generateRandom: crypto.getRandomValues,
			hash: (data: ArrayBuffer, alg: string) =>
				crypto.subtle.digest(alg, data),
			verifyJwt: verifyJwt,
			fetch,
			signJwt: signJwt([ providerJwkPriv as Jwk ])
		};
		const provider = new ItWalletProvider({ callbacks } as any);
		attestation = await provider.createItWalletAttestationJwt(
			attestationOptions
		);
		writeFileSync(
			attestationPath,
			attestation
		);
	}

	// check validity with sdk?

	return attestation;
}

function fromJwt(input: string): { [ key: string ]: unknown } {
    const parts = input.split('.');

	if (parts.length < 3)
		throw new SyntaxError("malformed jwt");

    const header = Buffer.from(parts[0]!, "base64url").toString();
    const payload = Buffer.from(parts[1]!, "base64url").toString();

    return {
		...JSON.parse(header),
		...JSON.parse(payload)
	};
}

async function toJwt(
	headerObj: { [ key: string ]: unknown },
	payloadObj: { [ key: string ]: unknown },
	key: JsonWebKey
): Promise<string> {
	const alg = key.alg ?? "ECDSA"
	const privateKey = await crypto.subtle.importKey(
		"jwk", key,
		{
			name: alg,
			namedCurve: key.crv!
		},
		true, ["sign"]
	);

	const header = Buffer.from(JSON.stringify(headerObj))
		.toString("base64url");
	const payload = Buffer.from(JSON.stringify(payloadObj))
		.toString("base64url");
	const signature = Buffer.from(
		await crypto.subtle.sign(
			{ name: alg, hash: "SHA-256" }, privateKey,
			Buffer.from(`${header}.${payload}`)
		)
	).toString("base64url");

    return `${header}.${payload}.${signature}`;
}
