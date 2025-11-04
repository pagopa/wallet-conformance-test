import { parse } from "@auth0/mdl";
import { Jwk } from "@pagopa/io-wallet-oauth2";
import { parseWithErrorHandling } from "@pagopa/io-wallet-oid-federation";
import { importJWK } from "jose";

import { Mdoc, mdocPayloadSchema, VerificationError } from "@/types";

export async function validateMdoc(
  credential: Buffer,
  issuerKey: Jwk,
): Promise<Mdoc> {
  const mdoc = parse(credential);
  const subs: string[] = [];

  for (const doc of mdoc.documents) {
    if (!doc) continue;

    if (!(await doc.issuerSigned.issuerAuth.verify(await importJWK(issuerKey))))
      throw new VerificationError("MDOC signature verification failed");

    for (const nameSpace in doc.issuerSigned.nameSpaces) {
      if (!doc.issuerSigned.nameSpaces[nameSpace]) continue;

      const items = doc.issuerSigned.nameSpaces[nameSpace];

      if (!items.find((item) => item.elementIdentifier === "issuing_country"))
        throw new VerificationError(
          `Missing mandatory 'issuing_country' in namespace ${nameSpace}`,
        );
      if (!items.find((item) => item.elementIdentifier === "issuing_authoity"))
        throw new VerificationError(
          `Missing mandatory 'issuing_authoity' in namespace ${nameSpace}`,
        );

      const sub = items.find(
        (item) => item.elementIdentifier === "sub",
      )?.elementValue;
      if (sub) subs.push(sub);
    }

    if (!doc.issuerSigned.issuerAuth.protectedHeaders.get(1))
      throw new VerificationError(
        "Missing algorithm identifier header: key '1' in protected headers",
      );
    if (!doc.issuerSigned.issuerAuth.unprotectedHeaders.get(33))
      throw new VerificationError(
        "Missing certificate: key '33' in unprotected headers",
      );

    const payload = JSON.parse(
      Buffer.from(doc.issuerSigned.issuerAuth.payload).toString(),
    );
    parseWithErrorHandling(
      mdocPayloadSchema,
      payload,
      "Error validating mdoc payload",
    );
  }

  return { document: mdoc, subs };
}
