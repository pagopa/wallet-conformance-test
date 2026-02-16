import {
  DeviceResponse,
  IssuerSignedDocument,
  MDLParseError,
  MDoc,
} from "@auth0/mdl";
import IssuerAuth from "@auth0/mdl/lib/mdoc/model/IssuerAuth";
import { PresentationDefinition } from "@auth0/mdl/lib/mdoc/model/PresentationDefinition";
import { parseWithErrorHandling, ValidationError } from "@pagopa/io-wallet-utils";
import { decode } from "cbor";

import { issuerSignedSchema, KeyPair } from "@/types";
import { IssuerSignedItem } from "@auth0/mdl/lib/mdoc/IssuerSignedItem";

/**
 * Creates a Verifiable Presentation (VP) token in mdoc format.
 *
 * This function generates a `DeviceResponse` according to the OID4VP standard.
 * The response includes the selected credentials from the mdoc, authenticated
 * with the device's private key.
 *
 * @param options The options for creating the mdoc VP token.
 * @returns A promise that resolves to an object containing the `DeviceResponse` encoded as a CBOR map.
 */
export async function createVpTokenMdoc({
  clientId,
  credential,
  devicePrivateKey,
  nonce,
  presentationDefinition,
  queryId,
  responseUri,
}: {
  clientId: string;
  credential: string;
  devicePrivateKey: KeyPair["privateKey"];
  nonce: string;
  presentationDefinition: PresentationDefinition;
  queryId: string;
  responseUri: string;
}) {
  const issuerSigned = parseMdoc(Buffer.from(credential, "base64url"));
  const issuerMDoc = new MDoc([issuerSigned]).encode();
  const walletNonce = Buffer.from(
    crypto.getRandomValues(new Uint8Array(16)),
  ).toString("base64url");

  const deviceResponse = await DeviceResponse.from(issuerMDoc)
    .usingPresentationDefinition(presentationDefinition)
    .usingSessionTranscriptForOID4VP(walletNonce, clientId, responseUri, nonce)
    .authenticateWithSignature(devicePrivateKey, "ES256")
    .sign();

  return {
    [queryId]: deviceResponse.encode(),
  };
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

    const nameSpaces = Object.entries(doc.nameSpaces).reduce(
      (prev, [nameSpace, items]) => ({
        ...prev,
        [nameSpace]: items.map((item) => new IssuerSignedItem(decode(item.value))),
      }),
      {},
    );
    if (issuerAuth.decodedPayload.version !== "1.0")
      throw new MDLParseError("The issuerAuth version must be '1.0'");

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
