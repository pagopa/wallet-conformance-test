import { Constructed, ObjectIdentifier, OctetString, Sequence } from "asn1js";
import {
  AlgorithmIdentifier,
  EncapsulatedContentInfo,
  id_ContentType_SignedData,
  IssuerAndSerialNumber,
  SignedData,
  SignerInfo,
} from "pkijs";

import type { LoadedPidMrtdPki } from "@/logic/pid-mrtd/pki";

import { bytesToBase64Url } from "@/logic/pid-mrtd/encoding";
import {
  type DataGroupHashEntry,
  encodeLdsSecurityObject,
} from "@/logic/pid-mrtd/lds-security-object";
import { initPkijsCryptoEngine } from "@/logic/pid-mrtd/pkijs-engine";

const ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

/**
 * Builds a CMS SignedData (DER) wrapping an LDS Security Object, signed with the mock DSC.
 */
export async function createSodCmsSignedData(
  pki: Pick<LoadedPidMrtdPki, "dscPkijsCertificate" | "dscPrivateKey">,
  dataGroupHashes: readonly DataGroupHashEntry[],
): Promise<Uint8Array> {
  initPkijsCryptoEngine();

  const ldsDer = encodeLdsSecurityObject(dataGroupHashes);
  const encapContentInfo = new EncapsulatedContentInfo({
    eContent: new OctetString({
      valueHex: Uint8Array.from(ldsDer).buffer,
    }),
    eContentType: "0.4.0.127.0.7.2.2.1",
  });

  const signedData = new SignedData({
    certificates: [pki.dscPkijsCertificate],
    encapContentInfo,
    signerInfos: [
      new SignerInfo({
        sid: new IssuerAndSerialNumber({
          issuer: pki.dscPkijsCertificate.issuer,
          serialNumber: pki.dscPkijsCertificate.serialNumber,
        }),
        signatureAlgorithm: new AlgorithmIdentifier({
          algorithmId: ECDSA_WITH_SHA256,
        }),
        version: 1,
      }),
    ],
    version: 1,
  });

  await signedData.sign(pki.dscPrivateKey, 0, "SHA-256");

  const sdSchema = signedData.toSchema(true);
  const cmsSequence = new Sequence({
    value: [
      new ObjectIdentifier({ value: id_ContentType_SignedData }),
      new Constructed({
        idBlock: { isConstructed: true, tagClass: 3, tagNumber: 0 },
        value: [sdSchema],
      }),
    ],
  });

  return new Uint8Array(cmsSequence.toBER(false));
}

/**
 * ECDSA P-256 signature over the MRTD PoP `challenge` (IAS private key).
 * Returns base64url-encoded raw R||S (FR-18 / annex §7).
 */
export async function signMrtdChallenge(
  challenge: string,
  iasPrivateKey: CryptoKey,
): Promise<string> {
  const data = new TextEncoder().encode(challenge);
  const signature = await crypto.subtle.sign(
    { hash: "SHA-256", name: "ECDSA" },
    iasPrivateKey,
    data,
  );
  return bytesToBase64Url(new Uint8Array(signature));
}
