import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwt } from "@sd-jwt/decode";
import { DisclosureData } from "@sd-jwt/types";
import { decode } from "cbor";
import { DcqlMdocCredential, DcqlQuery, DcqlSdJwtVcCredential } from "dcql";

import type { Logger } from "@/types/logger";

import { getDcqlQueryMatches, validateDcqlQuery } from "./dcql";

/**
 * Builds a Verifiable Presentation (VP) token by selecting credentials based on a DCQL query.
 *
 * @param credentials An array of credentials in SD-JWT format.
 * @param query The DCQL query to use for selecting credentials.
 * @param logger An optional logger instance for diagnostic output.
 * @returns A promise that resolves to a record mapping credential query IDs to the selected credentials.
 * @throws An error if the DCQL query cannot be satisfied or if a credential index is not found.
 */
export async function buildVpToken(
  credentials: string[],
  query: DcqlQuery.Input,
  logger?: Logger,
) {
  const queryResult = await validateDcqlQuery(credentials, query, logger);
  const matches = getDcqlQueryMatches(queryResult);

  return matches.reduce(
    (acc, [credentialQueryId, match]) => {
      const validCredential = match.valid_credentials[0];
      if (!validCredential) {
        throw new Error(
          `No valid credentials found for credential_query_id ${credentialQueryId}`,
        );
      }

      const credentialIndex = validCredential.input_credential_index;
      const credential = credentials[credentialIndex];
      if (!credential) {
        throw new Error(
          `Credential index ${credentialIndex} not found for credential_query_id ${credentialQueryId}`,
        );
      }

      acc[credentialQueryId] = credential;
      return acc;
    },
    {} as Record<string, string>,
  );
}

export function parseCredentialFromMdoc(
  credential: string,
): DcqlMdocCredential {
  const buffer = Buffer.from(credential, "base64url");

  const decoded = decode(buffer).documents[0];
  if (!decoded) {
    throw new Error("missing DeviceSignedDocument from MDoc DeviceResponse");
  }

  return {
    credential_format: "mso_mdoc",
    cryptographic_holder_binding: true,
    doctype: decoded.docType,
    namespaces: decoded.issuerSigned.nameSpaces,
  };
}

/**
 * Parses an SD-JWT credential and transforms it into the format required for DCQL processing.
 *
 * @param credential The credential in SD-JWT format.
 * @returns A promise that resolves to the parsed credential in `DcqlSdJwtVcCredential` format.
 * @throws An error if the credential format is unsupported or if the `vct` claim is missing.
 */
export async function parseCredentialFromSdJwt(
  credential: string,
): Promise<DcqlSdJwtVcCredential> {
  const { disclosures, jwt } = await decodeSdJwt(credential, digest);

  const claims = disclosures.reduce(
    (acc, disclosure) => {
      const disclosureData = disclosure.decode();
      const claim = disclosureData[1] as string;
      acc[claim] = disclosureData;
      return acc;
    },
    {} as Record<string, DisclosureData<unknown>>,
  );

  const credentialFormat = jwt.header.typ;
  if (credentialFormat !== "dc+sd-jwt") {
    throw new Error(`Unsupported credential format: ${credentialFormat}`);
  }

  const vct = jwt.payload.vct;
  if (typeof vct !== "string") {
    throw new Error("vct is missing or invalid in the credential payload");
  }

  return {
    claims: claims as DcqlSdJwtVcCredential["claims"],
    credential_format: credentialFormat,
    cryptographic_holder_binding: true,
    vct,
  };
}
