import { readFileSync, writeFileSync } from "node:fs";

import {
	ItWalletProvider,
	WalletAttestationOptions
} from "@pagopa/io-wallet-oid4vci";
import { SignJWT } from "jose";

import type { Config } from "@/types";
import {
	generateKey,
	verifyJwt,
	signJwtCallback
} from "@/logic";

/**
 * Loads a wallet attestation from the filesystem.
 * If the attestation is not found, a new one is generated and saved.
 *
 * @param wallet The wallet configuration.
 * @returns A promise that resolves to the wallet attestation JWT.
 */
export async function loadAttestation(
	wallet: Config["wallet"]
): Promise<string> {
	const attestationPath = `${wallet.wallet_attestations_storage_path}/${wallet.wallet_id}`;

	try {
		return readFileSync(attestationPath, "utf-8");
	} catch {
		console.info("missing wallet attestation: generating a new one");

		const providerKeyPair = await generateKey(
			`${wallet.backup_storage_path}/wallet_provider_jwks`
		);
		const unitKeyPair = await generateKey(
			`${wallet.backup_storage_path}/wallet_unit_jwks`
		);

		const trustChain = await new SignJWT(
			{ 
				jwks: {
					keys: [ providerKeyPair.publicKey ]
				}
			}
		).
		setProtectedHeader({ alg: "ES256" }).
		sign(providerKeyPair.privateKey);
		
		const attestationOptions: WalletAttestationOptions = {
			issuer: wallet.wallet_provider_base_url,
			signer: {
				walletProviderJwkPublicKid: providerKeyPair.privateKey.kid!,
				trustChain: [ trustChain ]
			},
			dpopJwkPublic: unitKeyPair.publicKey,
			walletName: wallet.wallet_name,
			walletLink: `${wallet.wallet_provider_base_url}/wallet`
		};
		const callbacks = {
			clientAuthentication: () => {},
			generateRandom: crypto.getRandomValues,
			hash: (data: ArrayBuffer, alg: string) =>
				crypto.subtle.digest(alg, data),
			verifyJwt: verifyJwt,
			fetch,
			signJwt: signJwtCallback([ providerKeyPair.privateKey ])
		};
		const provider = new ItWalletProvider({ callbacks });
		const attestation = await provider.createItWalletAttestationJwt(
			attestationOptions
		);
		writeFileSync(
			attestationPath,
			attestation
		);

		return attestation;
	}
}
