import {
  DeviceKey,
  Issuer,
  IssuerAuth,
  IssuerSigned,
  SignatureAlgorithm,
} from "@owf/mdoc";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import cbor from "cbor";
import { decodeJwt } from "jose";

import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  loadJsonDumps,
} from "@/logic";
import { mdocContext } from "@/logic/mdoc-context";
import { generateSRIHash } from "@/logic/sd-jwt";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";
import { Config, Credential, KeyPair, KeyPairJwk } from "@/types";

const { decode, encode, Tagged } = cbor;

export async function buildIssuerEntityConfiguration_V1_0(
  metadata: {
    iss: string;
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  keyPair: KeyPair,
): Promise<string> {
  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(metadata.trustAnchor);
  const issClaims = loadJsonDumps(
    "issuer_metadata.json",
    {
      issuer_base_url: metadata.iss,
      public_key: keyPair.publicKey,
      trust_anchor_base_url: trustAnchorBaseUrl,
    },
    ItWalletSpecsVersion.V1_0,
  );
  return createFederationMetadata({
    claims: issClaims,
    entityPublicJwk: keyPair.publicKey,
    signedJwks: keyPair,
  });
}

export async function buildMockMdlMdoc_V1_0(
  expiration: Date,
  deviceKey: KeyPairJwk,
  issuerCertificate: string,
  issuerKeyPair: KeyPair,
): Promise<Credential> {
  const claims = loadJsonDumps(
    "mDL.json",
    { expiration },
    ItWalletSpecsVersion.V1_0,
  );

  const signedDocument = await new Issuer("org.iso.18013.5.1.mDL", mdocContext)
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
      validityInfo: {
        signed: new Date(),
        validFrom: new Date(),
        validUntil: expiration,
      },
    });

  // The `status_assertion` mechanism used by IT-Wallet 1.0 is not part of
  // ISO 18013-5, so it cannot be passed to `Issuer.sign`. Splice it into the
  // MSO payload after signing (mock-only; invalidates the signature just as
  // the previous implementation did).
  const originalAuth = signedDocument.issuerAuth;
  const payloadWithStatus = encode(
    new Tagged(
      24,
      encode({
        ...decode(decode(Buffer.from(originalAuth.payload ?? [])).value),
        status: {
          status_assertion: {
            credential_hash_alg: "sha-256",
          },
        },
      }),
    ),
  );

  const issuerSigned = IssuerSigned.create({
    issuerAuth: IssuerAuth.create({
      payload: new Uint8Array(payloadWithStatus),
      protectedHeaders: originalAuth.protectedHeaders,
      signature: originalAuth.signature,
      unprotectedHeaders: originalAuth.unprotectedHeaders,
    }),
    issuerNamespaces: signedDocument.issuerNamespaces,
  });

  return {
    compact: issuerSigned.encodedForOid4Vci,
    parsed: issuerSigned,
    typ: "mso_mdoc",
  };
}

export async function buildMockSdJwt_V1_0(
  metadata: {
    iss: string;
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  expiration: Date,
  unitKey: KeyPairJwk,
  certificate: string,
  keyPair: KeyPair,
): Promise<Credential> {
  const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(metadata.trustAnchor);
  const taEntityConfiguration = await createSubordinateTrustAnchorMetadata({
    entityPublicJwk: keyPair.publicKey,
    federationTrustAnchor: metadata.trust,
    sub: metadata.iss,
    trustAnchorBaseUrl,
    walletVersion: ItWalletSpecsVersion.V1_0,
  });

  const issEntityConfiguration = await buildIssuerEntityConfiguration_V1_0(
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
    ItWalletSpecsVersion.V1_0,
  );

  const disclosureFrame = {
    _sd: [
      "family_name",
      "given_name",
      "birth_date",
      "expiry_date",
      "birth_place",
      "nationalities",
      "personal_administrative_number",
      "tax_id_code",
    ],
  };

  const vct =
    "https://pre.ta.wallet.ipzs.it/vct/v1.0.0/personidentificationdata";
  const vctIntegrity = generateSRIHash(vct);

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
