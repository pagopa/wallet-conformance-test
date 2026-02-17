import {
  DeviceResponse,
  IssuerSignedDocument,
  MDLParseError,
  MDoc,
} from "@auth0/mdl";
import IssuerAuth from "@auth0/mdl/lib/mdoc/model/IssuerAuth";
import { PresentationDefinition } from "@auth0/mdl/lib/mdoc/model/PresentationDefinition";
import {
  parseWithErrorHandling,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { decode } from "cbor";
import { DcqlQuery } from "dcql";

import { issuerSignedSchema, KeyPair } from "@/types";

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
  dcqlQuery,
  devicePrivateKey,
  nonce,
  responseUri,
}: {
  clientId: string;
  credential: string;
  dcqlQuery: DcqlQuery.Input;
  devicePrivateKey: KeyPair["privateKey"];
  nonce: string;
  responseUri: string;
}) {
  const issuerSigned = parseMdoc(Buffer.from(credential, "base64url"));

  const issuerMDoc = new MDoc([issuerSigned]);
  const walletNonce = Buffer.from(
    crypto.getRandomValues(new Uint8Array(16)),
  ).toString("base64url");

  const presentationDefinition = convertDcqlToPresentationDefinition(
    dcqlQuery,
    issuerSigned.docType,
  );

  const deviceResponse = await DeviceResponse.from(issuerMDoc)
    .usingPresentationDefinition(presentationDefinition)
    .usingSessionTranscriptForOID4VP(walletNonce, clientId, responseUri, nonce)
    .authenticateWithSignature(devicePrivateKey, "ES256")
    .sign();

  return {
    [presentationDefinition.id]: deviceResponse.encode(),
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
        [nameSpace]: items.map((item) => decode(item.value)),
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

/**
 * Converts a DCQL query into a Presentation Definition for mdoc.
 *
 * This function searches the DCQL query for a credential request matching the provided `docType`.
 * If a match is found, it constructs a `PresentationDefinition` with an `input_descriptors` array
 * that specifies the requested fields (namespaces and their elements) based on the claims requested
 * in the DCQL query.
 *
 * @param {DcqlQuery.Input} query - The DCQL query containing the credential requests.
 * @param {string} docType - The document type to match in the DCQL query (e.g., "org.iso.18013.5.1.mDL").
 * @returns {PresentationDefinition} A `PresentationDefinition` object derived from the matching credential query.
 * @throws {Error} If no matching credential query is found for the given `docType` or if the DCQL query structure is invalid.
 */
function convertDcqlToPresentationDefinition(
  query: DcqlQuery.Input,
  docType: string,
): PresentationDefinition {
  const credentialQuery = query.credentials?.find(
    (c) => c.format === "mso_mdoc" && c.meta?.doctype_value === docType,
  );

  if (!credentialQuery) {
    throw new Error(
      `No credential query found for docType: ${docType} in the provided DCQL query.`,
    );
  }

  // Extract namespaces and elements from claims
  const fields =
    credentialQuery.claims
      ?.map((claim: any) => {
        if ((!claim.namespace || !claim.claim_name) && !claim.path) {
          return null;
        }

        return {
          intent_to_retain: true,
          path: claim.path
            ? [claim.path.map((p: string) => `['${p}']`).join("")]
            : [`['${claim.namespace}']`, `['${claim.claim_name}']`],
        };
      })
      .filter((f) => f !== null) || [];

  return {
    id: credentialQuery.id,
    input_descriptors: [
      {
        constraints: {
          fields: fields,
          limit_disclosure: "required",
        },
        format: {
          mso_mdoc: {
            alg: ["ES256"],
          },
        },
        id: docType,
      },
    ],
  };
}
