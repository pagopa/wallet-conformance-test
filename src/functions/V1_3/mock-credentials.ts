import { DataItem, Document } from "@auth0/mdl";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { decode, encode, Tagged } from "cbor";
import { decodeJwt } from "jose";

import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  getTrustMarks,
  loadJsonDumps,
} from "@/logic";
import { generateSRIHash } from "@/logic/sd-jwt";
import { fetchExternalSubordinateStatement } from "@/trust-anchor/external-ta-registration";
import {
  isExternalTrustAnchor,
  resolveTrustAnchorBaseUrl,
} from "@/trust-anchor/trust-anchor-resolver";
import { Config, Credential, KeyPair, KeyPairJwk } from "@/types";

export async function buildIssuerEntityConfiguration_V1_3(
  metadata: {
    iss: string;
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  keyPair: KeyPair,
): Promise<string> {
  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(metadata.trustAnchor);
  const trust_marks = await getTrustMarks(
    trustAnchorBaseUrl,
    metadata.trust.federation_trust_anchors_jwks_path,
    metadata.iss,
  );
  const issClaims = loadJsonDumps(
    "issuer_metadata.json",
    {
      issuer_base_url: metadata.iss,
      public_key: keyPair.publicKey,
      trust_anchor_base_url: trustAnchorBaseUrl,
      trust_marks,
    },
    ItWalletSpecsVersion.V1_3,
  );
  return createFederationMetadata({
    claims: issClaims,
    entityPublicJwk: keyPair.publicKey,
    signedJwks: keyPair,
  });
}

export async function buildMockMdlMdoc_V1_3(
  expiration: Date,
  deviceKey: KeyPairJwk,
  issuerCertificate: string,
  issuerKeyPair: KeyPair,
  issuerBaseUrl: string,
): Promise<Credential> {
  const claims = loadJsonDumps(
    "mDL.json",
    { expiration },
    ItWalletSpecsVersion.V1_3,
  );

  const document = await new Document("org.iso.18013.5.1.mDL")
    .addIssuerNameSpace("org.iso.18013.5.1", claims)
    .useDigestAlgorithm("SHA-256")
    .addValidityInfo({
      signed: new Date(),
      validFrom: new Date(),
      validUntil: expiration,
    })
    .addDeviceKeyInfo({ deviceKey })
    .sign({
      alg: "ES256",
      issuerCertificate,
      issuerPrivateKey: issuerKeyPair.privateKey,
    });

  const issuerSigned = document.prepare().get("issuerSigned");
  const payloadWithStatus = encode(
    new Tagged(
      24,
      encode({
        ...decode(decode(issuerSigned.issuerAuth[2]).value),
        status: {
          status_list: {
            idx: 0,
            uri: `${issuerBaseUrl}/status-list`,
          },
        },
      }),
    ),
  );
  issuerSigned.issuerAuth[2] = payloadWithStatus;
  const parsed = document as any;
  parsed.issuerSigned.issuerAuth.payload = payloadWithStatus;

  const nameSpaces = new Map<string, Tagged[]>();
  for (const [namespace, items] of issuerSigned["nameSpaces"] as Map<
    string,
    DataItem[]
  >) {
    nameSpaces.set(
      namespace,
      items.map((item) => new Tagged(24, item.buffer)),
    );
  }

  const cborIssuerSigned = encode({
    issuerAuth: issuerSigned["issuerAuth"],
    nameSpaces,
  });
  const compact = cborIssuerSigned.toString("base64url");

  return {
    compact,
    parsed: document,
    typ: "mso_mdoc",
  };
}

export async function buildMockSdJwt_V1_3(
  metadata: {
    iss: string;
    network: Config["network"];
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  expiration: Date,
  unitKey: KeyPairJwk,
  certificate: string,
  keyPair: KeyPair,
): Promise<Credential> {
  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(metadata.trustAnchor);
  const taEntityConfiguration = isExternalTrustAnchor(
    metadata.trustAnchor.external_ta_url,
  )
    ? await fetchExternalSubordinateStatement(
        trustAnchorBaseUrl,
        metadata.iss,
        metadata.network,
      )
    : await createSubordinateTrustAnchorMetadata({
        entityPublicJwk: keyPair.publicKey,
        federationTrustAnchor: metadata.trust,
        sub: metadata.iss,
        trustAnchorBaseUrl: trustAnchorBaseUrl,
        walletVersion: ItWalletSpecsVersion.V1_3,
      });

  const issEntityConfiguration = await buildIssuerEntityConfiguration_V1_3(
    metadata,
    keyPair,
  );

  const issuer = {
    keyPair,
    trust_chain: [issEntityConfiguration, taEntityConfiguration],
  };

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

  const claims = loadJsonDumps(
    "pid.json",
    { expiration },
    ItWalletSpecsVersion.V1_3,
  );

  const disclosureFrame = {
    _sd: [
      "family_name",
      "given_name",
      "birthdate",
      "date_of_expiry",
      "place_of_birth",
      "nationalities",
      "personal_administrative_number",
    ],
  };

  const vct = "urn:eudi:pid:it:1";
  const vctIntegrity = generateSRIHash(vct);

  const credential = await sdjwt.issue(
    {
      cnf: { jwk: unitKey },
      exp: Math.floor(expiration.getTime() / 1000),
      iat: Math.floor(Date.now() / 1000),
      iss: metadata.iss,
      status: {
        status_list: {
          idx: 0,
          uri: `${metadata.iss}/status-list`,
        },
      },
      sub: unitKey.kid,
      vct,
      "vct#integrity": vctIntegrity,
      verification: {
        assurance_level: "high",
        trust_framework: "it_cie",
      },
      ...claims,
    },
    disclosureFrame,
    {
      header: {
        kid: issuer.keyPair.privateKey.kid,
        trust_chain: issuer.trust_chain,
        typ: "dc+sd-jwt",
        x5c: [certificate],
      },
    },
  );

  return {
    compact: credential,
    parsed: await decodeJwt(credential),
    typ: "dc+sd-jwt",
  };
}
