<<<<<<< HEAD
import { IssuerSignedDocument, MDLParseError } from "@auth0/mdl";
import IssuerAuth from "@auth0/mdl/lib/mdoc/model/IssuerAuth";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { ValidationError } from "@pagopa/io-wallet-utils";
import { decode } from "cbor";

import { issuerSignedSchema } from "@/types";

/**
 * Parses a mobile document (mdoc) from a Buffer into an IssuerSignedDocument object.
 *
 * This function attempts to decode the provided Buffer as a CBOR object and then validates its
 * structure against a predefined schema. It constructs an `IssuerSignedDocument` by processing
 * the issuer authentication data and namespaces. The function ensures that the mdoc conforms to
 * the expected format and version.
 *
 * @param {Buffer} credential - The raw mdoc credential as a Buffer.
 * @returns {IssuerSignedDocument} The parsed mdoc as an `IssuerSignedDocument` object.
 * @throws {MDLParseError} If the credential buffer cannot be decoded or parsed as a valid mdoc.
 * @throws {ValidationError} If the decoded mdoc fails schema validation.
 */
export function parseMdoc(credential: Buffer): IssuerSignedDocument {
  try {
    const doc = parseWithErrorHandling(
      issuerSignedSchema,
      decode(credential),
      "Error extracting issuer signed document",
    );

    const issuerAuth = new IssuerAuth(
      doc.issuerAuth[0],
      doc.issuerAuth[1],
      doc.issuerAuth[2],
      doc.issuerAuth[3],
    );

    if (issuerAuth.decodedPayload.version !== "1.0")
      throw new MDLParseError("The issuerAuth version must be '1.0'");

    const nameSpaces = Object.entries(doc.nameSpaces).reduce(
      (prev, [nameSpace, items]) => ({
        ...prev,
        [nameSpace]: items.map((item) => decode(item.value)),
      }),
      {},
    );

    return new IssuerSignedDocument(issuerAuth.decodedPayload.docType, {
      ...doc,
      issuerAuth,
      nameSpaces,
    });
  } catch (e) {
    if (e instanceof ValidationError) throw e;

    const err = e as Error;
    throw new MDLParseError(`Unable to decode mdoc: ${err.message}`);
  }
=======
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
>>>>>>> 4e22faa (feat: add validation logic for mdoc)
}
