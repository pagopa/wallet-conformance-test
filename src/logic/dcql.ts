import { DcqlQuery, type DcqlQueryResult } from "dcql";

import { CredentialWithKey, Logger } from "@/types";

import { parseCredentialFromMdoc, parseCredentialFromSdJwt } from "./vpToken";

type DcqlMatchSuccess = Extract<
  DcqlQueryResult.CredentialMatch,
  { success: true }
>;

/**
 * Extracts successful matches from a DCQL query result.
 *
 * @example of matches structure
 * [
 *   [
 *     "credential_id_example",
 *     {
 *       "success": true,
 *       "credential_query_id": "credential_id_example",
 *       "valid_credentials": [
 *         {
 *           "success": true,
 *           "input_credential_index": 0,
 *           "trusted_authorities": {
 *             "success": true
 *           },
 *           "meta": {
 *             "success": true,
 *             "output": {
 *               "credential_format": "dc+sd-jwt",
 *               "vct": "urn:eudi:pid:1",
 *               "cryptographic_holder_binding": true
 *             }
 *           },
 *           "claims": {
 *             "success": true,
 *             "valid_claim_sets": [
 *               {
 *                 "success": true,
 *                 "output": {
 *                     ..........
 *                 },
 *                 "valid_claim_indexes": [
 *                   0,
 *                   1
 *                 ]
 *               }
 *             ],
 *             "valid_claims": [
 *               {
 *                 "success": true,
 *                 "claim_index": 0,
 *                 "output": {
 *                     ..........
 *                 }
 *               },
 *               {
 *                 "success": true,
 *                 "claim_index": 1,
 *                 "output": {
 *                     ..........
 *                 }
 *               }
 *             ]
 *           }
 *         }
 *       ]
 *     }
 *   ]
 * ]
 * @param queryResult The result of a DCQL query.
 * @returns An array of successful credential matches.
 */
export function getDcqlQueryMatches(queryResult: DcqlQueryResult) {
  const matches = Object.entries(queryResult.credential_matches).filter(
    ([, match]) => match.success === true,
  );

  return matches as [string, DcqlMatchSuccess][];
}

/**
 * Validates a DCQL query against a set of credentials.
 *
 * This function first parses and validates the DCQL query itself. Then, it parses
 * the provided credentials (in SD-JWT or MDOC format) and checks if they can satisfy the query.
 *
 * @param credentials An array of credentials in SD-JWT or MDOC format.
 * @param query The DCQL query to validate.
 * @param logger An optional logger instance for diagnostic output.
 * @returns A promise that resolves with the query result if validation is successful.
 * @throws An error if the query is invalid or cannot be satisfied by the provided credentials.
 */
export async function validateDcqlQuery(
  credentials: CredentialWithKey[],
  query: DcqlQuery.Input,
  logger?: Logger,
) {
  const parsedQuery = DcqlQuery.parse(query);
  DcqlQuery.validate(parsedQuery);
  logger?.info(`Dcql Query requested: ${JSON.stringify(parsedQuery)}`);

  const parsedCredentials = await Promise.all(
    credentials.map(async (credential) => {
      if (credential.typ === "dc+sd-jwt")
        return await parseCredentialFromSdJwt(credential.credential);

      if (credential.typ === "mso_mdoc")
        return parseCredentialFromMdoc(credential.credential);

      throw new Error(`credential type not implemented: ${credential.typ}`);
    }),
  );

  // Log credentials available in the wallet
  logger?.info(
    `Credentials available in the wallet (${parsedCredentials.length}):`,
  );
  parsedCredentials.forEach((c, i) => {
    logger?.info(
      `  [${i + 1}] format: ${c.credential_format},`,
      c.credential_format !== "mso_mdoc"
        ? `vct: ${c.vct}`
        : `docType: ${c.doctype}`,
    );
  });

  // Log credentials requested by the DCQL query
  const requestedCredentials = parsedQuery.credentials;
  logger?.info(
    `DCQL query requests (${requestedCredentials.length}) credential(s):`,
  );
  requestedCredentials.forEach((c, i) => {
    const vctValues =
      "meta" in c && c.meta && "vct_values" in c.meta && c.meta.vct_values
        ? c.meta.vct_values.join(", ")
        : "any";
    const doctypeValues =
      "meta" in c && c.meta && "doctype_value" in c.meta && c.meta.doctype_value
        ? c.meta.doctype_value
        : "any";
    logger?.info(
      `  [${i + 1}] id: "${c.id}", format: ${c.format},`,
      c.format !== "mso_mdoc"
        ? `vct: ${vctValues}`
        : `docType: ${doctypeValues}`,
    );
  });

  const queryResult = DcqlQuery.query(parsedQuery, parsedCredentials);
  if (!queryResult.can_be_satisfied) {
    logger?.warn(
      `Tip: verify that the credential types in the wallet satisfy the DCQL query. Mocked credentials are stored in the "data/credentials" directory.`,
    );

    const cause = formatDcqlFailCause(
      credentials,
      queryResult.credential_matches,
    );
    throw new Error(
      `DCQL query validation failed: The provided credentials do not satisfy the DCQL query.\n${cause}`,
    );
  }

  return queryResult;
}

function formatDcqlFailCause(
  credentials: CredentialWithKey[],
  credentialMatches: Record<string, unknown>,
): string {
  const errorMessage: string[] = [];
  for (const [k, result] of Object.entries(credentialMatches)) {
    const queryResult = result as {
      credential_query_id: string;
      failed_credentials: unknown[];
    };

    errorMessage.push(
      `  Query index: ${k}, query id: ${queryResult.credential_query_id}\n`,
    );

    for (const failed of queryResult.failed_credentials) {
      const queryFailed = failed as {
        claims: {
          failed_claims: {
            issues: Record<string, string[]>;
          }[];
          success: boolean;
        };
        input_credential_index: number;
        meta: {
          issues: Record<string, string[]>;
          success: boolean;
        };
        trusted_authorities: {
          issues: Record<string, string[]>;
          success: boolean;
        };
      };

      errorMessage.push(
        `    Credential ${credentials[queryFailed.input_credential_index]?.id}:\n`,
      );

      errorMessage.push(`    → Trusted authorities `);
      if (queryFailed.trusted_authorities.success)
        errorMessage.push(`passed\n`);
      else {
        errorMessage.push(`failed ❌\n`);
        errorMessage.push(
          `      ${Object.entries(queryFailed.trusted_authorities.issues)
            .map(([attribute, issues]) => `${attribute}: ${issues}`)
            .join("\n      ")}`,
        );
      }

      errorMessage.push(`    → Claims `);
      if (queryFailed.claims.success) errorMessage.push(`passed\n`);
      else {
        errorMessage.push(`failed ❌\n`);

        for (const failedClaim of queryFailed.claims.failed_claims)
          errorMessage.push(
            `      ${Object.entries(failedClaim.issues)
              .map(([claim, issues]) => `${claim}: ${issues}`)
              .join(", ")}\n`,
          );
      }

      errorMessage.push(`    → Meta `);
      if (queryFailed.meta.success) errorMessage.push(`passed\n`);
      else {
        errorMessage.push(`failed ❌\n`);
        errorMessage.push(
          `      ${Object.entries(queryFailed.meta.issues)
            .map(([attribute, issues]) => `${attribute}: ${issues}`)
            .join("\n      ")}`,
        );
      }
    }
  }

  return errorMessage.join("");
}
