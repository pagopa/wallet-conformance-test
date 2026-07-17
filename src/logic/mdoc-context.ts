import { CoseKey, MdocContext, SignatureAlgorithm } from "@owf/mdoc";
import * as x509 from "@peculiar/x509";
import { exportJWK } from "jose";
import nodeCrypto, {
  createECDH,
  createHmac,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  KeyObject,
  sign as nodeSign,
  verify as nodeVerify,
  timingSafeEqual,
} from "node:crypto";

const coseAlgorithmToHash: Partial<Record<number, string>> = {
  [SignatureAlgorithm.ES256]: "sha256",
  [SignatureAlgorithm.ES384]: "sha384",
  [SignatureAlgorithm.ES512]: "sha512",
};

function coseKeyToKeyObject(key: CoseKey, isPrivate: boolean): KeyObject {
  const jwk = { ...key.jwk };
  if (!isPrivate) delete jwk.d;
  return isPrivate
    ? createPrivateKey({ format: "jwk", key: jwk })
    : createPublicKey({ format: "jwk", key: jwk });
}

function resolveHash(
  algorithm: SignatureAlgorithm | undefined,
  key: CoseKey,
): string | undefined {
  const alg = algorithm ?? key.algorithm;
  if (alg === SignatureAlgorithm.EdDSA) return undefined;
  return (alg !== undefined && coseAlgorithmToHash[alg]) || "sha256";
}

function toX509Certificate(certificate: Uint8Array): x509.X509Certificate {
  return new x509.X509Certificate(Buffer.from(certificate).toString("base64"));
}

/**
 * Node.js implementation of the pluggable crypto context required by
 * `@owf/mdoc`, backed by `node:crypto`, `jose` and `@peculiar/x509`.
 */
export const mdocContext: MdocContext = {
  cose: {
    mac0: {
      authenticate: async ({ key, toBeAuthenticated }) => {
        const keyBytes = key instanceof CoseKey ? key.privateKey : key;
        return new Uint8Array(
          createHmac("sha256", Buffer.from(keyBytes))
            .update(toBeAuthenticated)
            .digest(),
        );
      },
      verify: async ({ key, tag, toBeAuthenticated }) => {
        const keyBytes = key instanceof CoseKey ? key.privateKey : key;
        const expected = createHmac("sha256", Buffer.from(keyBytes))
          .update(toBeAuthenticated)
          .digest();
        return (
          tag.byteLength === expected.byteLength &&
          timingSafeEqual(Buffer.from(tag), expected)
        );
      },
    },
    sign1: {
      sign: async ({ algorithm, key, toBeSigned }) =>
        new Uint8Array(
          nodeSign(resolveHash(algorithm, key), toBeSigned, {
            dsaEncoding: "ieee-p1363",
            key: coseKeyToKeyObject(key, true),
          }),
        ),
      verify: async ({ algorithm, key, signature, toBeVerified }) =>
        nodeVerify(
          resolveHash(algorithm, key),
          toBeVerified,
          {
            dsaEncoding: "ieee-p1363",
            key: coseKeyToKeyObject(key, false),
          },
          signature,
        ),
    },
  },
  crypto: {
    digest: async ({ bytes, digestAlgorithm }) =>
      new Uint8Array(await nodeCrypto.subtle.digest(digestAlgorithm, bytes)),
    hdkf: async ({
      digestAlgorithm = "SHA-256",
      info,
      privateKey,
      publicKey,
      salt,
    }) => {
      const ecdh = createECDH("prime256v1");
      ecdh.setPrivateKey(Buffer.from(privateKey));
      const sharedSecret = ecdh.computeSecret(Buffer.from(publicKey));
      const hash = digestAlgorithm.replace("SHA-", "sha");
      return new Uint8Array(hkdfSync(hash, sharedSecret, salt, info, 32));
    },
    random: (length) => nodeCrypto.getRandomValues(new Uint8Array(length)),
  },
  fetch,
  x509: {
    getCertificateData: async ({ certificate }) => {
      const cert = toX509Certificate(certificate);
      const thumbprint = Buffer.from(await cert.getThumbprint()).toString(
        "hex",
      );
      return {
        issuerName: cert.issuerName.toString(),
        notAfter: cert.notAfter,
        notBefore: cert.notBefore,
        pem: cert.toString(),
        serialNumber: cert.serialNumber,
        subjectName: cert.subjectName.toString(),
        thumbprint,
      };
    },
    getIssuerNameField: ({ certificate, field }) =>
      toX509Certificate(certificate).issuerName.getField(field),
    getPublicKey: async ({ certificate }) => {
      const cert = toX509Certificate(certificate);
      const cryptoKey = await cert.publicKey.export();
      return CoseKey.fromJwk(
        (await exportJWK(cryptoKey)) as Record<string, unknown>,
      );
    },
    verifyCertificateChain: async ({ now, trustedCertificates, x5chain }) => {
      if (x5chain.length === 0 || !x5chain[0])
        throw new Error("Certificate chain is empty");

      const leaf = toX509Certificate(x5chain[0]);
      const builder = new x509.X509ChainBuilder({
        certificates: [...x5chain, ...(trustedCertificates ?? [])].map(
          toX509Certificate,
        ),
      });

      // The built chain is reversed: the `x5chain` input has the leaf
      // certificate first, while `@peculiar/x509` returns it last.
      const chain = (await builder.build(leaf)).reverse();
      if (chain.length < x5chain.length)
        throw new Error(
          "Could not parse the full chain. Likely due to incorrect ordering",
        );

      const referenceTime = now ?? new Date();
      for (const cert of chain) {
        if (
          cert.notBefore.getTime() > referenceTime.getTime() ||
          cert.notAfter.getTime() < referenceTime.getTime()
        )
          throw new Error(
            `Certificate ${cert.subjectName.toString()} is not valid at ${referenceTime.toISOString()}`,
          );
      }

      let previousCertificate: undefined | x509.X509Certificate;
      for (const cert of chain) {
        await cert.verify({ publicKey: previousCertificate?.publicKey });
        previousCertificate = cert;
      }

      return { chain: chain.map((cert) => new Uint8Array(cert.rawData)) };
    },
  },
};
