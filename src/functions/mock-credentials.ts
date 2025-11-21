import type { DisclosureFrame } from "@sd-jwt/types";

import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { exportPKCS8, exportSPKI, importJWK } from "jose";
import { asn1, pki } from "node-forge";

import { generateKey } from "@/logic";
import { KeyPair, KeyPairJwk } from "@/types";

export async function createMockSdJwt(
  iss: string,
  backupPath: string,
  issuerArg?: { certificate: string; keyPair: KeyPair },
  unitKeyArg?: KeyPairJwk,
): Promise<string> {
  let issuer;
  if (!issuerArg) {
    const keyPair = await generateKey(`${backupPath}/issuer.jwk`);
    const privatePem = await exportPKCS8(
      (await importJWK(keyPair.privateKey)) as CryptoKey,
    );
    const publicPem = await exportSPKI(
      (await importJWK(keyPair.publicKey)) as CryptoKey,
    );

    const certificatePem = pki.createCertificate();
    certificatePem.publicKey = pki.publicKeyFromPem(publicPem);
    certificatePem.serialNumber = "01";
    certificatePem.setSubject([
      { name: "wallet-conformance-test", value: "issuer.example.com" },
    ]);
    certificatePem.setIssuer(certificatePem.subject.attributes);

    certificatePem.sign(pki.privateKeyFromPem(privatePem));
    const certificate = Buffer.from(
      asn1.toDer(pki.certificateToAsn1(certificatePem)).getBytes(),
      "binary",
    ).toString("base64");

    issuer = {
      certificate,
      keyPair,
    };
  } else {
    issuer = issuerArg;
  }

  const unitKey =
    unitKeyArg ??
    (await generateKey(`${backupPath}/wallet_unit.jwk`)).publicKey;

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

  const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000 * 355);

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

  // TODO: Check required payload and header for sd-jwt
  const credential = await sdjwt.issue(
    {
      cnf: { jwk: unitKey },
      exp: Math.floor(expiration.getTime() / 1000),
      iat: Math.floor(Date.now() / 1000),
      iss,
      status: {
        status_assertion: {
          credential_hash_alg: "sha-256",
        },
        status_list: {
          idx: 1,
          uri: "https://status_list.example.com",
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
        kid: issuer.keyPair.privateKey,
        typ: "dc+sd-jwt",
        x5c: [issuer.certificate],
      },
    },
  );

  return credential;
}

async function generateSRIHash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  const hashArray = Array.from(new Uint8Array(hashBuffer));

  const hashBinary = hashArray
    .map((byte) => String.fromCharCode(byte))
    .join("");

  const base64Hash = Buffer.from(hashBinary).toString("base64");

  return `sha256-${base64Hash}`;
}
