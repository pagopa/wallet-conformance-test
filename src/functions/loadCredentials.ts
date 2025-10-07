import { readdirSync, readFileSync } from "node:fs";

import { Verifier } from "@auth0/mdl";
import { SDJwt, SDJwtInstance } from "@sd-jwt/core";
import { ES256, digest, generateSalt } from "@sd-jwt/crypto-nodejs";

/**
 * Loads credentials from a specified directory, verifies them, and returns the valid ones.
 * The function supports both SD-JWT and MDOC credential formats.
 *
 * @param path - The directory path where credential files are located.
 * @param types - An array of credential type names, used to filter and identify credentials.
 * @param publicKey - The public key (in JWK format) used for verifying SD-JWT signatures.
 * @param caCertPath - The file path to the Certificate Authority (CA) certificate for verifying MDOC credentials.
 * @returns A promise that resolves to a record object where keys are the credential filenames
 *          and values are the credential data (string for SD-JWT, ArrayBuffer for MDOC).
 */
export async  function loadCredentials(
	path: string,
	types: string[],
	publicKey: JsonWebKey,
	caCertPath: string
): Promise<Record<string, string | ArrayBuffer>> {
	const files = readdirSync(path);
	const credentials: Record<string, string | ArrayBuffer> = {};

	for (const file of files) {
		const fileName = file.split("/").pop();
		// Skip if the file is not a recognized credential type
		if (!fileName || !types.find(name => name === fileName)){
			console.error(`current issuer does not support ${fileName} credential type`);
			continue;
		}

		
		// First, attempt to verify the credential as a SD-JWT
		try {
			const credential = readFileSync(`${path}/${file}`, "utf-8");
			const jwt = await SDJwt.extractJwt(credential);
			if (!jwt.payload || !jwt.payload["_sd_alg"])
				throw new Error("credential parsing failed");
	
			// Mock signer as it's not needed for verification
			const signer = () => "";
			const verifier = await ES256.getVerifier(publicKey);
			
			const sdjwt = new SDJwtInstance({
				signer,
				signAlg: jwt.payload["_sd_alg"] as string,
				verifier,
				hasher: digest,
				saltGenerator: generateSalt
			});

			// If validation is successful, add it to the credentials record
			if (!await sdjwt.validate(jwt["encoded"]))
				throw new Error("credential validation failed");

			credentials[fileName] = credential;
			continue; // Move to the next file
		} catch(e) {
			const err = e as Error
			console.error(`${file} was not a valid sd-jwt credential: ${err.message}`);
		}
		
		// If SD-JWT verification fails, attempt to verify it as an MDOC
		try {
			const credential = readFileSync(`${path}/${file}`);
			const cert = readFileSync(caCertPath, "utf-8");
			const verifier = new Verifier([cert]);
			await verifier.verify(credential);

			// If validation is successful, add it to the credentials record
			credentials[fileName] = credential.buffer;
		} catch(e) {
			throw e
			const err = e as Error
			console.error(`${file} was not a valid mdoc credential: ${err.message}`);
		}
	}

	return credentials;
}