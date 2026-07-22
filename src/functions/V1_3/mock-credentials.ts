import { DeviceKey, Issuer, SignatureAlgorithm } from "@owf/mdoc";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { decodeJwt } from "jose";

import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  getTrustMarks,
  loadJsonDumps,
} from "@/logic";
import { mdocContext } from "@/logic/mdoc-context";
import { generateSRIHash } from "@/logic/sd-jwt";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";
import { Config, Credential, KeyPair, KeyPairJwk } from "@/types";

/**
 * Builds the mocked Credential Issuer entity configuration.
 *
 * Shared by V1_3 and V1_4 — only the dumps directory differs between them.
 */
export async function buildIssuerEntityConfiguration(
  metadata: {
    iss: string;
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  keyPair: KeyPair,
  version:
    | ItWalletSpecsVersion.V1_3
    | ItWalletSpecsVersion.V1_4 = ItWalletSpecsVersion.V1_3,
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
    version,
  );
  return createFederationMetadata({
    claims: issClaims,
    entityPublicJwk: keyPair.publicKey,
    signedJwks: keyPair,
  });
}

/**
 * Builds a mocked mDL MDOC credential.
 *
 * Shared by V1_3 and V1_4 — only the dumps directory differs between them.
 */
export async function buildMockMdlMdoc(
  expiration: Date,
  deviceKey: KeyPairJwk,
  issuerCertificate: string,
  issuerKeyPair: KeyPair,
  issuerBaseUrl: string,
  version:
    | ItWalletSpecsVersion.V1_3
    | ItWalletSpecsVersion.V1_4 = ItWalletSpecsVersion.V1_3,
): Promise<Credential> {
  const claims = loadJsonDumps("mDL.json", { expiration }, version);

  const issuerSigned = await new Issuer("org.iso.18013.5.1.mDL", mdocContext)
    .addIssuerNamespace("org.iso.18013.5.1", claims)
    .sign({
      algorithm: SignatureAlgorithm.ES256,
      certificates: [new Uint8Array(Buffer.from(issuerCertificate, "base64"))],
      deviceKeyInfo: {
        deviceKey: DeviceKey.fromJwk(
          deviceKey as unknown as Record<string, unknown>,
        ) as DeviceKey,
      },
      digestAlgorithm: "SHA-256",
      signingKey: issuerKeyPair.privateKey as unknown as Record<
        string,
        unknown
      >,
      status: {
        statusList: {
          idx: 0,
          uri: `${issuerBaseUrl}/status-list`,
        },
      },
      validityInfo: {
        signed: new Date(),
        validFrom: new Date(),
        validUntil: expiration,
      },
    });

  return {
    compact: issuerSigned.encodedForOid4Vci,
    parsed: issuerSigned,
    typ: "mso_mdoc",
  };
}

/**
 * Builds a mocked PID SD-JWT credential.
 *
 * Shared by V1_3 and V1_4 — only the dumps directory differs between them.
 */
export async function buildMockSdJwt(
  metadata: {
    iss: string;
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  expiration: Date,
  unitKey: KeyPairJwk,
  certificate: string,
  keyPair: KeyPair,
  version:
    | ItWalletSpecsVersion.V1_3
    | ItWalletSpecsVersion.V1_4 = ItWalletSpecsVersion.V1_3,
): Promise<Credential> {
  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(metadata.trustAnchor);
  const taEntityConfiguration = await createSubordinateTrustAnchorMetadata({
    entityPublicJwk: keyPair.publicKey,
    federationTrustAnchor: metadata.trust,
    sub: metadata.iss,
    trustAnchorBaseUrl,
    walletVersion: version,
  });

  const issEntityConfiguration = await buildIssuerEntityConfiguration(
    metadata,
    keyPair,
    version,
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

  const claims = loadJsonDumps("pid.json", { expiration }, version);

  const disclosureFrame = {
    _sd: [
      "family_name",
      "given_name",
      "birthdate",
      "date_of_expiry",
      "place_of_birth",
      "nationalities",
      "personal_administrative_number",
      "tax_id_code",
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
        assurance_level: "https://trust-anchor.eid-wallet.example.it/loa/high",
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
