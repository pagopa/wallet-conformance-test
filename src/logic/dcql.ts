import { DcqlQuery, type DcqlQueryResult } from "dcql";

import { parseCredentialFromSdJwt } from "./vpToken";

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
 * the provided SD-JWT credentials and checks if they can satisfy the query.
 *
 * @param credentials An array of credentials in SD-JWT format.
 * @param query The DCQL query to validate.
 * @returns A promise that resolves with the query result if validation is successful.
 * @throws An error if the query is invalid or cannot be satisfied by the provided credentials.
 */
export async function validateDcqlQuery(
  credentials: string[],
  query: DcqlQuery.Input,
) {
  const parsedQuery = DcqlQuery.parse(query);
  DcqlQuery.validate(parsedQuery);

  const parsedCredentials = await Promise.all(
    credentials.map((credential) => parseCredentialFromSdJwt(credential)),
  );

  const queryResult = DcqlQuery.query(parsedQuery, parsedCredentials);
  if (!queryResult.can_be_satisfied) {
    throw new Error(
      "DCQL query validation failed: The provided credentials do not satisfy the DCQL query",
    );
  }

  return queryResult;
}
