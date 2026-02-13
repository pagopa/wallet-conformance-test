import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwt } from "@sd-jwt/decode";
import { DisclosureData } from "@sd-jwt/types";
import { DcqlMdocCredential, DcqlQuery, DcqlSdJwtVcCredential } from "dcql";

import type { Logger } from "@/types/logger";

import { CredentialWithKey, DcqlMatchSuccess, VpTokenOptions } from "@/types";

import { getDcqlQueryMatches, validateDcqlQuery } from "./dcql";
import { createVpTokenMdoc, parseMdoc } from "./mdoc";
import { createVpTokenSdJwt } from "./sd-jwt";

/**
 * Builds a Verifiable Presentation (VP) token by selecting credentials based on a DCQL query.
 *
 * @param credentials An array of credentials (e.g., SD-JWT and MDOC) encoded as strings.
 * @param query The DCQL query to use for selecting credentials.
 * @param logger An optional logger instance for diagnostic output.
 * @param options The parameters needed for creating vpTokens from the parsed credentials.
 * @returns A promise that resolves to a record mapping credential query IDs to the selected credentials.
 * @throws An error if the DCQL query cannot be satisfied or if a credential index is not found.
 */
export async function buildVpToken(
  credentials: CredentialWithKey[],
  query: DcqlQuery.Input,
  options: Omit<VpTokenOptions, "credential" | "dcqlQuery" | "dpopJwk">,
  logger?: Logger,
): Promise<Record<string, string>> {
  const queryResult = await validateDcqlQuery(credentials, query, logger);
  const matches: [string, DcqlMatchSuccess][] =
    getDcqlQueryMatches(queryResult);

  return matches.reduce(async (acc, [credentialQueryId, match]) => {
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

    const queryCredential = query.credentials.find(
      (c) => c.id === credentialQueryId,
    );
    if (!queryCredential)
      throw new Error(
        `Credential ${credentialQueryId} requested but missing from query`,
      );

    if (credential.typ === "dc+sd-jwt")
      return {
        ...acc,
        [credentialQueryId]: await createVpTokenSdJwt({
          ...options,
          credential: credential.credential,
          dpopJwk: credential.dpopJwk,
        }),
      };

    if (credential.typ === "mso_mdoc") {
      const mdocQuery = {
        ...query,
        credentials: [queryCredential],
      };

      return {
        ...acc,
        ...(await createVpTokenMdoc({
          ...options,
          credential: credential.credential,
          dcqlQuery: mdocQuery,
          dpopJwk: credential.dpopJwk,
        })),
      };
    }
  }, {});
}

export function parseCredentialFromMdoc(
  credential: string,
): DcqlMdocCredential {
  const buffer = Buffer.from(credential, "base64url");

  const document = parseMdoc(buffer);
  if (!document) {
    throw new Error("missing DeviceSignedDocument from MDoc DeviceResponse");
  }

  return {
    credential_format: "mso_mdoc",
    cryptographic_holder_binding: true,
    doctype: document.docType,
    namespaces: document.issuerSigned
      .nameSpaces as unknown as DcqlMdocCredential["namespaces"],
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
