import {
  CoseKey,
  DeviceRequest,
  DocRequest,
  Holder,
  IssuerSigned,
  ItemsRequest,
  MdlParseError,
  SessionTranscript,
} from "@owf/mdoc";
import { DcqlQuery } from "dcql";

import { VpTokenOptions } from "@/types";

import { mdocContext } from "./mdoc-context";

interface DcqlMdocClaim {
  claim_name?: string;
  namespace?: string;
  path?: string[];
}

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
export async function createVpTokenMdoc(
  options: VpTokenOptions,
): Promise<string> {
  const issuerSigned = parseMdoc(Buffer.from(options.credential, "base64url"));
  const docType = issuerSigned.issuerAuth.mobileSecurityObject.docType;

  const walletNonce = Buffer.from(
    crypto.getRandomValues(new Uint8Array(16)),
  ).toString("base64url");

  const deviceRequest = convertDcqlToDeviceRequest(options.dcqlQuery, docType);
  if (!deviceRequest) {
    return "";
  }

  const sessionTranscript = await SessionTranscript.forOid4VpDraft18(
    {
      clientId: options.client_id,
      mdocGeneratedNonce: walletNonce,
      responseUri: options.responseUri,
      verifierGeneratedNonce: options.nonce,
    },
    mdocContext,
  );

  const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
    {
      deviceRequest,
      issuerSigned: [issuerSigned],
      sessionTranscript,
      signature: {
        signingKey: CoseKey.fromJwk(
          options.dpopJwk as unknown as Record<string, unknown>,
        ),
      },
    },
    mdocContext,
  );

  return deviceResponse.encodedForOid4Vp;
}

/**
 * Parses a mobile document (mdoc) from a Buffer into an IssuerSigned object.
 *
 * This function attempts to decode the provided Buffer as a CBOR-encoded
 * `IssuerSigned` structure, validating it against the schemas bundled with
 * `@owf/mdoc`. It also ensures the Mobile Security Object declares the
 * expected version.
 *
 * @param {Buffer} credential - The raw mdoc credential as a Buffer.
 * @returns {IssuerSigned} The parsed mdoc as an `IssuerSigned` object.
 * @throws {MdlParseError} If the credential buffer cannot be decoded or parsed as a valid mdoc.
 */
export function parseMdoc(credential: Buffer): IssuerSigned {
  try {
    const issuerSigned = IssuerSigned.decode(credential);

    if (issuerSigned.issuerAuth.mobileSecurityObject.version !== "1.0")
      throw new MdlParseError("The issuerAuth version must be '1.0'");

    return issuerSigned;
  } catch (e) {
    if (e instanceof MdlParseError) throw e;

    const message = e instanceof Error ? e.message : String(e);
    throw new MdlParseError(`Unable to decode mdoc: ${message}`);
  }
}

/**
 * Converts a DCQL query into an ISO 18013-5 DeviceRequest for mdoc.
 *
 * This function searches the DCQL query for a credential request matching the
 * provided `docType`. If a match is found, it constructs a `DeviceRequest`
 * whose `ItemsRequest` lists the requested data elements (namespaces and
 * their element identifiers) based on the claims requested in the DCQL query.
 *
 * @param {DcqlQuery.Input} query - The DCQL query containing the credential requests.
 * @param {string} docType - The document type to match in the DCQL query (e.g., "org.iso.18013.5.1.mDL").
 * @returns {DeviceRequest | undefined} A `DeviceRequest` derived from the matching credential query, or `undefined` when no request matches.
 */
function convertDcqlToDeviceRequest(
  query: DcqlQuery.Input,
  docType: string,
): DeviceRequest | undefined {
  const credentialQuery = query.credentials?.find(
    (c) => c.format === "mso_mdoc" && c.meta?.doctype_value === docType,
  );

  if (!credentialQuery) {
    return;
  }

  // Extract namespaces and elements from claims
  const claims = credentialQuery.claims as readonly DcqlMdocClaim[] | undefined;
  const namespaces = new Map<string, Map<string, boolean>>();
  for (const claim of claims ?? []) {
    const path =
      claim.path ??
      (claim.namespace && claim.claim_name
        ? [claim.namespace, claim.claim_name]
        : undefined);

    const [namespace, elementIdentifier] = path ?? [];
    if (!namespace || !elementIdentifier) continue;

    const elements = namespaces.get(namespace) ?? new Map<string, boolean>();
    elements.set(elementIdentifier, true);
    namespaces.set(namespace, elements);
  }

  return DeviceRequest.create({
    docRequests: [
      DocRequest.create({
        itemsRequest: ItemsRequest.create({ docType, namespaces }),
      }),
    ],
  });
}
