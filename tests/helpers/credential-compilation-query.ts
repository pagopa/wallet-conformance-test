import type { DcqlQuery } from "dcql";

export interface CredentialCompilationClaim {
  id?: string;
  mandatory?: "true" | boolean;
  path: string[];
}

export interface CredentialCompilationConfiguration {
  claims?: CredentialCompilationClaim[];
  credential_metadata?: {
    claims?: CredentialCompilationClaim[];
  };
  format: "dc+sd-jwt" | "mso_mdoc";
  vct?: string;
}

/**
 * Builds the DCQL credential query used by CI_014 from issuer metadata.
 *
 * Metadata claims are descriptive by default. Only claims explicitly marked
 * mandatory are queried, and the IT-Wallet identifier alternatives are
 * represented as DCQL claim sets when both alternatives are mandatory.
 */
export function buildCredentialCompilationQuery(
  configuration: CredentialCompilationConfiguration,
  options: { credentialQueryId: string; isLegacy: boolean },
): DcqlQuery.Input {
  const metadataClaims = options.isLegacy
    ? configuration.claims
    : configuration.credential_metadata?.claims;

  if (!metadataClaims) {
    throw new Error(
      "missing claims from issuer's supported credential configuration",
    );
  }

  const mandatoryClaims = metadataClaims.filter(isMandatoryClaim);
  const hasAdministrativeNumberAlternative =
    mandatoryClaims.some((claim) =>
      isClaimAtPath(
        claim,
        "personal_administrative_number",
        configuration.format,
      ),
    ) &&
    mandatoryClaims.some((claim) =>
      isClaimAtPath(claim, "tax_id_code", configuration.format),
    );

  const claims = mandatoryClaims.map((claim, index) => ({
    ...(hasAdministrativeNumberAlternative
      ? { id: getClaimId(claim, index) }
      : {}),
    path: claim.path,
  }));

  let claimSets: [string[], string[]] | undefined;
  if (hasAdministrativeNumberAlternative) {
    const taxIdIndex = mandatoryClaims.findIndex((claim) =>
      isClaimAtPath(claim, "tax_id_code", configuration.format),
    );
    const personalAdministrativeNumberIndex = mandatoryClaims.findIndex(
      (claim) =>
        isClaimAtPath(
          claim,
          "personal_administrative_number",
          configuration.format,
        ),
    );
    const taxIdClaim = mandatoryClaims[taxIdIndex];
    const personalAdministrativeNumberClaim =
      mandatoryClaims[personalAdministrativeNumberIndex];
    if (!taxIdClaim || !personalAdministrativeNumberClaim) {
      throw new Error(
        "tax_id_code and personal_administrative_number claim metadata is incomplete",
      );
    }
    const taxIdClaimId = getClaimId(taxIdClaim, taxIdIndex);
    const personalAdministrativeNumberClaimId = getClaimId(
      personalAdministrativeNumberClaim,
      personalAdministrativeNumberIndex,
    );
    const commonClaimIds = mandatoryClaims
      .map((claim, index) => ({ claim, id: getClaimId(claim, index) }))
      .filter(
        ({ claim }) =>
          !isClaimAtPath(claim, "tax_id_code", configuration.format) &&
          !isClaimAtPath(
            claim,
            "personal_administrative_number",
            configuration.format,
          ),
      )
      .map(({ id }) => id);

    claimSets = [
      [...commonClaimIds, taxIdClaimId],
      [...commonClaimIds, personalAdministrativeNumberClaimId],
    ];
  }

  if (configuration.format === "dc+sd-jwt") {
    const credentialQuery: Extract<
      DcqlQuery.Input["credentials"][number],
      { format: "dc+sd-jwt" | "vc+sd-jwt" }
    > = {
      format: configuration.format,
      id: options.credentialQueryId,
      ...(claims.length > 0 ? { claims } : {}),
      ...(claimSets ? { claim_sets: claimSets } : {}),
      ...(configuration.vct
        ? { meta: { vct_values: [configuration.vct] } }
        : {}),
    };

    return { credentials: [credentialQuery] };
  }

  const mdocClaims = mandatoryClaims.map((claim, index) => {
    const [namespace, claimName] = claim.path;
    if (
      claim.path.length !== 2 ||
      namespace === undefined ||
      claimName === undefined
    ) {
      throw new Error(
        `mso_mdoc claim path must contain namespace and claim name: ${claim.path.join(".")}`,
      );
    }

    return {
      ...(hasAdministrativeNumberAlternative
        ? { id: getClaimId(claim, index) }
        : {}),
      path: [namespace, claimName] as [string, string],
    };
  });

  const credentialQuery: Extract<
    DcqlQuery.Input["credentials"][number],
    { format: "mso_mdoc" }
  > = {
    format: configuration.format,
    id: options.credentialQueryId,
    ...(mdocClaims.length > 0 ? { claims: mdocClaims } : {}),
    ...(claimSets ? { claim_sets: claimSets } : {}),
  };

  return { credentials: [credentialQuery] };
}

function getClaimId(claim: CredentialCompilationClaim, index: number): string {
  if (claim.id) return claim.id;

  const pathId = claim.path.join("-").replace(/[^A-Za-z0-9_-]/g, "_");
  return pathId.length > 0 ? pathId : `claim-${index}`;
}

function isClaimAtPath(
  claim: CredentialCompilationClaim,
  path: string,
  format: CredentialCompilationConfiguration["format"],
): boolean {
  if (format === "dc+sd-jwt") {
    return claim.path.length === 1 && claim.path[0] === path;
  }

  return claim.path.length === 2 && claim.path[1] === path;
}

function isMandatoryClaim(claim: CredentialCompilationClaim): boolean {
  return claim.mandatory === true || claim.mandatory === "true";
}
