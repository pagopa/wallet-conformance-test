import { IssuerSignedDocument, MDLParseError } from "@auth0/mdl";
import IssuerAuth from "@auth0/mdl/lib/mdoc/model/IssuerAuth";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { ValidationError } from "@pagopa/io-wallet-utils";
import { decode } from "cbor";

import {
  CredentialError,
  issuerSignedSchema,
  Mdoc,
  mdocPayloadSchema,
} from "@/types";

/**
 * Validates a mobile document (mdoc) by ensuring it conforms to the required structure and contains
 * mandatory fields. This function parses the mdoc, checks for the presence of essential attributes
 * such as 'issuing_country' and 'issuing_authority' within each namespace, and verifies the issuer
 * authentication data. It also validates the mdoc's payload against a predefined schema.
 *
 * @param {Buffer} credential - The mdoc credential to be validated, provided as a Buffer.
 * @returns {Promise<Mdoc>} A promise that resolves with an object containing the parsed mdoc and a
 * list of subjects (subs) found in the document.
 * @throws {CredentialError} If mandatory fields are missing from the mdoc, such as algorithm
 * identifiers or certificates.
 * @throws {Error} If the mdoc payload is malformed or fails schema validation.
 */
export async function validateMdoc(credential: Buffer): Promise<Mdoc> {
  const mdoc = parse(credential);
  const subs: string[] = [];

  for (const nameSpace in mdoc.issuerSigned.nameSpaces) {
    if (!mdoc.issuerSigned.nameSpaces[nameSpace]) continue;

    const items = mdoc.issuerSigned.nameSpaces[nameSpace];

    if (!items.find((item) => item.elementIdentifier === "issuing_country"))
      throw new CredentialError(
        `Missing mandatory 'issuing_country' in namespace ${nameSpace}`,
      );
    if (!items.find((item) => item.elementIdentifier === "issuing_authority"))
      throw new CredentialError(
        `Missing mandatory 'issuing_authoity' in namespace ${nameSpace}`,
      );

    const sub = items.find(
      (item) => item.elementIdentifier === "sub",
    )?.elementValue;
    if (sub) subs.push(sub); // TODO: check if sub must be different for every namespace or just every document
  }

  if (!mdoc.issuerSigned.issuerAuth.protectedHeaders.get(1))
    throw new CredentialError(
      "Missing algorithm identifier header: key '1' in protected headers",
    );
  if (!mdoc.issuerSigned.issuerAuth.unprotectedHeaders.get(33))
    throw new CredentialError(
      "Missing certificate: key '33' in unprotected headers",
    );

  parseWithErrorHandling(
    mdocPayloadSchema,
    mdoc.issuerSigned.issuerAuth.decodedPayload,
    "Error validating mdoc payload",
  );

  return { document: mdoc, subs };
}

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
function parse(credential: Buffer): IssuerSignedDocument {
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
}
