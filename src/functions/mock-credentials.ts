import type { DisclosureFrame } from "@sd-jwt/types";

import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { decodeJwt } from "jose";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  loadJsonDumps,
  loadJwks,
} from "@/logic";
import { Credential } from "@/types";

export async function createMockSdJwt(
  metadata: {
    iss: string;
    trustAnchorBaseUrl: string;
    trustAnchorJwksPath: string;
  },
  backupPath: string,
  credentialsPath: string,
): Promise<Credential> {
  const keyPair = await loadJwks(backupPath, "issuer_pid_mocked_jwks");

  const taEntityConfiguration = await createSubordinateTrustAnchorMetadata({
    entityPublicJwk: keyPair.publicKey,
    federationTrustAnchorsJwksPath: metadata.trustAnchorJwksPath,
    sub: metadata.iss,
    trustAnchorBaseUrl: metadata.trustAnchorBaseUrl,
  });

  const issClaims = loadJsonDumps("issuer_metadata.json", {
    issuer_base_url: metadata.iss,
    public_key: keyPair.publicKey,
    trust_anchor_base_url: metadata.trustAnchorBaseUrl,
  });
  const issEntityConfiguration = await createFederationMetadata({
    claims: issClaims,
    entityPublicJwk: keyPair.publicKey,
    signedJwks: keyPair,
  });

  const issuer = {
    keyPair,
    trust_chain: [issEntityConfiguration, taEntityConfiguration],
  };

  const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";
  const { publicKey: unitKey } = await loadJwks(
    backupPath,
    `${credentialIdentifier}_jwks`,
  );

  const signer = await ES256.getSigner(issuer.keyPair.privateKey);
  const verifier = await ES256.getVerifier(unitKey);

  const sdjwt = new SDJwtVcInstance({
    hashAlg: "sha-256",
    hasher: digest,
    saltGenerator: generateSalt,
    signAlg: ES256.alg,
    signer,
    verifier,
  });

  const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000 * 365);

  // TODO: Check required claims for pid
  const claims = {
    birth_date: "1980-01-10",
    birth_place: "Roma",
    expiry_date: expiration.toISOString().slice(0, 10),
    family_name: "Rossi",
    given_name: "Mario",
    nationalities: ["IT"],
    personal_administrative_number: "XX00000XX",
  };

  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: [
      "family_name",
      "given_name",
      "birth_date",
      "birth_place",
      "nationalities",
      "personal_administrative_number",
    ],
  };

  const vct = "urn:eudi:pid:1";
  const vctIntegrity = await generateSRIHash(vct);

  const credential = await sdjwt.issue(
    {
      cnf: { jwk: unitKey },
      exp: Math.floor(expiration.getTime() / 1000),
      iat: Math.floor(Date.now() / 1000),
      iss: metadata.iss,
      status: {
        status_assertion: {
          credential_hash_alg: "sha-256",
        },
      },
      sub: unitKey.kid,
      vct,
      "vct#integrity": vctIntegrity,
      ...claims,
    },
    disclosureFrame,
    {
      header: {
        kid: issuer.keyPair.privateKey.kid,
        trust_chain: issuer.trust_chain,
        typ: "dc+sd-jwt",
      },
    },
  );

  writeFileSync(`${credentialsPath}/${credentialIdentifier}`, credential);
  return {
    compact: credential,
    parsed: await decodeJwt(credential),
    typ: "dc+sd-jwt",
  };
}

async function generateSRIHash(content: string): Promise<string> {
  const digest = createHash("sha256").update(content).digest("base64");
  return `sha256-${digest}`;
}
