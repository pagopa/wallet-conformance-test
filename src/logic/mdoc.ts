import {
  DeviceResponse,
  IssuerSignedDocument,
  MDLParseError,
  MDoc,
} from "@auth0/mdl";
import { DataItem } from "@auth0/mdl/lib/cbor/DataItem";
import { IssuerSignedItem } from "@auth0/mdl/lib/mdoc/IssuerSignedItem";
import IssuerAuth from "@auth0/mdl/lib/mdoc/model/IssuerAuth";
import { PresentationDefinition } from "@auth0/mdl/lib/mdoc/model/PresentationDefinition";
import {
  parseWithErrorHandling,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { decode, encode, Tagged } from "cbor";
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
  // const base64 = credential.replace(/-/g, "+").replace(/_/g, "/");
  // const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
  // const issuerSigned = parseMdoc(Buffer.from(padded, "base64"));
  const issuerSigned = parseMdoc(Buffer.from(credential, "base64url"));

  const issuerMDoc = new MDoc([issuerSigned]).encode();
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
        [nameSpace]: items.map((item) => {
          // Debugging item structure
          // console.log(`Processing item in ${nameSpace}:`, item);
          // Helper to create mapped DataItem
          const createMappedIssuerSignedItem = (
            buffer: Buffer | Uint8Array,
            decoded: any,
          ) => {
            const mapping: Record<string, string> = {
              "0": "digestID",
              "1": "random",
              "2": "elementIdentifier",
              "3": "elementValue",
            };

            const mappedData = new Map();
            // decoded is likely an Object if cbor.decode() used default settings.
            // keys might be "0", "1"...
            for (const [key, value] of Object.entries(decoded)) {
              const mapKey = mapping[key] || key;
              mappedData.set(mapKey, value);
            }

            const dataItem = new DataItem({
              buffer: buffer,
              data: mappedData,
            });
            return new IssuerSignedItem(dataItem);
          };

          if (item instanceof Tagged) {
            if (Buffer.isBuffer(item.value)) {
              return createMappedIssuerSignedItem(
                item.value,
                decode(item.value),
              );
            } else {
              // item.value is already decoded.
              // We need to re-encode to get buffer? Or construct DataItem without buffer (if allowed)?
              // IssuerSignedItem needs buffer for verification usually.
              // If we don't have original buffer, verification might fail if re-encoding differs.
              // But for now, let's assume we can map it.
              // We don't have the buffer easily if it was auto-decoded.
              // Let's assume we can skip buffer or re-encode.
              // But `IssuerSignedItem.encode()` returns `.buffer`.
              return createMappedIssuerSignedItem(
                encode(item.value),
                item.value,
              );
            }
          }
          // If not tagged, check if buffer
          if (Buffer.isBuffer(item)) {
            return createMappedIssuerSignedItem(item, decode(item));
          }

          // Fallback: assume item is the data map
          // If it's the data map, we likely don't have the buffer.
          return createMappedIssuerSignedItem(encode(item), item);
        }),
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
    // Enhanced logging for debugging
    console.error("MDL Decoding Error:", err);
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
      ?.map((claim) => {
        // Expecting claim.path to be an array like ["namespace", "element"]
        // mdoc claims in DCQL for mso_mdoc format are typically addressed by namespace and element identifier.
        // We assume a convention where the path's first element is the namespace and the second is the element.
        // If the path structure differs, this logic might need adjustment based on specific DCQL profile for mdoc.
        if (!claim.namespace || !claim.claim_name || !claim.path) {
          // Fallback or skip if structure isn't as expected, or handle top-level claims if valid
          return null;
        }
        return {
          intent_to_retain: true,
          path: claim.path ?? [claim.namespace, claim.claim_name],
        };
      })
      .filter(
        (f): f is { intent_to_retain: boolean; path: string[] } => f !== null,
      ) || [];

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
            alg: ["ES256"], // Defaulting to ES256, could be parameterized or extracted if specified
          },
        },
        id: docType,
      },
    ],
  };
}
