import type { DcqlQuery } from "dcql";

import type { DcqlClaimPath, DcqlValidCredential } from "@/types";

export function getSelectedSdJwtClaimPaths(
  credentialQuery: DcqlQuery.Input["credentials"][number],
  validCredential: DcqlValidCredential,
): DcqlClaimPath[] {
  if (!credentialQuery.claims) return [];

  const validClaimSet = validCredential.claims.valid_claim_sets.find(
    (claimSet) => claimSet.valid_claim_indexes,
  );
  if (!validClaimSet?.valid_claim_indexes) return [];

  return validClaimSet.valid_claim_indexes.flatMap((claimIndex) => {
    const claimQuery = credentialQuery.claims?.[claimIndex];
    const validClaim = validCredential.claims.valid_claims?.find(
      (claim) => claim.claim_index === claimIndex,
    );

    if (!claimQuery || !("path" in claimQuery) || !validClaim) return [];

    return expandClaimPath(claimQuery.path, validClaim.output);
  });
}

function expandClaimPath(
  path: readonly (null | number | string)[],
  output: unknown,
  prefix: DcqlClaimPath = [],
): DcqlClaimPath[] {
  const segment = path[0];
  if (segment === undefined) return [prefix];

  if (typeof segment === "string") {
    if (!isRecord(output) || !(segment in output)) return [];

    return expandClaimPath(path.slice(1), output[segment], [
      ...prefix,
      segment,
    ]);
  }

  if (typeof segment === "number") {
    if (!Array.isArray(output)) return [];

    const item = output[segment];
    if (item === undefined || item === null) return [];

    return expandClaimPath(path.slice(1), item, [...prefix, segment]);
  }

  if (!Array.isArray(output)) return [];

  return output.flatMap((item, index) =>
    item === undefined || item === null
      ? []
      : expandClaimPath(path.slice(1), item, [...prefix, index]),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
