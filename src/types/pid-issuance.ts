import { z } from "zod";

import {
  PID_CREDENTIAL_CONFIGURATION_ID,
  PidIssuanceModeNotConfiguredError,
} from "@/errors";
export { PID_CREDENTIAL_CONFIGURATION_ID };

/**
 * Accepts INI/env string values ("true"/"1"/"false"/"0") or real booleans.
 * Mirrors {@link zBooleanFromString} in `config.ts` to avoid a circular import.
 */
const zBooleanFromString = z.union([z.boolean(), z.stringbool()]);

/**
 * Discriminator for the PID issuance flow, exposed via `[issuance_pid].mode`.
 *
 * - `none`   → standard (Q)EAA issuance flow; the `[issuance_pid]` section can
 *              be omitted entirely. All existing tests must keep passing.
 * - `l2plus` → SPID/CIEid substantial authentication with the full MRTD PoP
 *              chain (init → validation JWT → verify → browser callback).
 * - `l3`     → CIE+PIN high-LoA authentication, no MRTD PoP steps.
 *
 * The legacy `l2` mode (substantial without MRTD) is intentionally excluded
 * from this iteration — see `B.1_progetto_di_modifica_per_implementazione`.
 */
export const pidIssuanceModeSchema = z.enum(["none", "l2plus", "l3"]);
export type PidIssuanceMode = z.infer<typeof pidIssuanceModeSchema>;

/**
 * INI shape of the `[issuance_pid]` section, validated with Zod.
 *
 * Identity attributes are inline (no external file). `superRefine` enforces
 * the conditional requirements coming from the B_1 functional spec:
 *
 *   - `mode != none`   → core identity fields (FR-4) are required
 *   - `mode == l2plus` → MRTD-specific fields `mrz` and
 *                        `personal_administrative_number` (NUN) are also
 *                        required (FR-4 / FR-5)
 *
 * Format-level validation is intentionally permissive (non-empty strings,
 * ISO-8601 date, RFC-compliant email) so that test fixtures don't break on
 * regional variations of MRZ / NUN encodings. Stricter checks will be added
 * by REQ-03 (`src/logic/pid-mrtd/`) when the data is actually consumed.
 */
export const pidIssuanceSchema = z
  .object({
    birthdate: z.iso.date().optional(),

    /**
     * B1-6.4: opt-in flag that adds an `it_l2+document_proof` entry to the PAR
     * for `mode = l2plus` (post REQ-00). Default off — when unset the PAR is
     * unchanged, so existing L2+ tests keep passing. No effect for `l3`.
     */
    document_proof_enabled: zBooleanFromString.optional(),
    /**
     * B1-6.4: maps to the `it_l2+document_proof` `idphinting` field — the IdP the
     * wallet intends to authenticate against. Required when
     * `document_proof_enabled` is set for `l2plus`.
     */
    document_proof_idphinting: z.url().optional(),
    /**
     * B1-6.4: maps to the `it_l2+document_proof` `challenge_redirect_uri` field
     * (named `multi_step_redirect_uri` in the current online spec) — the
     * wallet's challenge endpoint. Required when `document_proof_enabled` is set
     * for `l2plus`.
     */
    document_proof_redirect_uri: z.url().optional(),

    email: z.email().optional(),
    family_name: z.string().min(1).optional(),
    given_name: z.string().min(1).optional(),
    /**
     * When set, overrides the derived flag `mode !== "none"` used by REQ-05
     * orchestrator branching. Align with linee guida `MOCK_MRTD_ENABLED`.
     */
    mock_mrtd_enabled: zBooleanFromString.optional(),
    mode: pidIssuanceModeSchema.default("none"),
    mrz: z.string().min(1).optional(),
    nationalities: z.array(z.string().min(1)).optional(),

    personal_administrative_number: z.string().min(1).optional(),
    phone_number: z.string().min(1).optional(),

    place_of_birth: z.string().min(1).optional(),
    tax_id_code: z.string().min(1).optional(),
  })
  .superRefine((data, ctx) => {
    if (data.mode === "none") {
      return;
    }

    const requiredIdentityFields = [
      "given_name",
      "family_name",
      "tax_id_code",
      "birthdate",
      "place_of_birth",
    ] as const;

    for (const field of requiredIdentityFields) {
      if (!data[field]) {
        ctx.addIssue({
          code: "custom",
          message: `[issuance_pid] '${field}' is required when mode = '${data.mode}'`,
          path: [field],
        });
      }
    }

    if (data.mode === "l2plus") {
      if (!data.mrz) {
        ctx.addIssue({
          code: "custom",
          message: "[issuance_pid] 'mrz' is required when mode = 'l2plus'",
          path: ["mrz"],
        });
      }
      if (!data.personal_administrative_number) {
        ctx.addIssue({
          code: "custom",
          message:
            "[issuance_pid] 'personal_administrative_number' (NUN) is required when mode = 'l2plus'",
          path: ["personal_administrative_number"],
        });
      }

      // B1-6.4: when the document-proof flag is on, its two fields are required.
      if (data.document_proof_enabled) {
        if (!data.document_proof_redirect_uri) {
          ctx.addIssue({
            code: "custom",
            message:
              "[issuance_pid] 'document_proof_redirect_uri' is required when 'document_proof_enabled' is set for mode = 'l2plus'",
            path: ["document_proof_redirect_uri"],
          });
        }
        if (!data.document_proof_idphinting) {
          ctx.addIssue({
            code: "custom",
            message:
              "[issuance_pid] 'document_proof_idphinting' is required when 'document_proof_enabled' is set for mode = 'l2plus'",
            path: ["document_proof_idphinting"],
          });
        }
      }
    } else if (data.document_proof_enabled) {
      // Flag only applies to l2plus; flag it as a misconfiguration otherwise.
      ctx.addIssue({
        code: "custom",
        message:
          "[issuance_pid] 'document_proof_enabled' is only valid when mode = 'l2plus'",
        path: ["document_proof_enabled"],
      });
    }
  });

export type PidIssuanceConfig = z.infer<typeof pidIssuanceSchema>;

/**
 * FR-3: rejects PID in `credential_types[]` without a configured `[issuance_pid].mode`.
 */
export function assertPidIssuanceCredentialGuard(
  credentialTypes: readonly string[],
  issuancePid: PidIssuanceConfig,
): void {
  if (
    configRequestsPidIssuance(credentialTypes) &&
    issuancePid.mode === "none"
  ) {
    throw new PidIssuanceModeNotConfiguredError();
  }
}

/**
 * Returns true when the issuance test profile targets PID credentials.
 */
export function configRequestsPidIssuance(
  credentialTypes: readonly string[],
): boolean {
  return credentialTypes.includes(PID_CREDENTIAL_CONFIGURATION_ID);
}

/**
 * Static identity attributes sourced from `[issuance_pid]`, consumed by the
 * mock IdP and the virtual CIE factory (`src/logic/pid-mrtd/`, REQ-03).
 *
 * Core fields are required once `mode` is `l2plus` or `l3` (enforced by
 * `pidIssuanceSchema.superRefine`). `mrz` and `personal_administrative_number`
 * are optional here because `l3` does not use MRTD; REQ-03 enforces them when
 * building DG1/SOD for `l2plus`.
 */
export const pidIdentityConfigSchema = z.object({
  birthdate: z.iso.date(),
  email: z.email().optional(),
  family_name: z.string().min(1),
  given_name: z.string().min(1),
  mrz: z.string().min(1).optional(),
  nationalities: z.array(z.string().min(1)).optional(),
  personal_administrative_number: z.string().min(1).optional(),
  phone_number: z.string().min(1).optional(),
  place_of_birth: z.string().min(1),
  tax_id_code: z.string().min(1),
});

export type PidIdentityConfig = z.infer<typeof pidIdentityConfigSchema>;

/**
 * Runtime state for the L2+ MRTD PoP sub-flow (`mode = l2plus` only).
 *
 * Populated incrementally by `MockEidLoaInjectionAuth`, `MrtdPopRequest`,
 * `MrtdPopValidation`, and `MrtdBrowserCallback` steps (REQ-04). Remains
 * `undefined` for `mode = none` and `mode = l3` (FR-7).
 *
 * All fields are optional in REQ-01 so partial orchestrator runs can carry
 * intermediate state; REQ-04 step tests will tighten required subsets per step.
 */
export const pidExtensionStateSchema = z.object({
  challenge: z.string().min(1).optional(),
  finalRedirectUri: z.string().min(1).optional(),
  htm: z.string().min(1).optional(),
  htuInit: z.string().min(1).optional(),
  htuVerify: z.string().min(1).optional(),
  mrtdAuthSession: z.string().min(1).optional(),
  mrtdPopJwtNonce: z.string().min(1).optional(),
  mrtdPopNonce: z.string().min(1).optional(),
  mrtdProofJwt: z.string().min(1).optional(),
  mrtdValPopNonce: z.string().min(1).optional(),
  mrz: z.string().min(1).optional(),
  state: z.string().min(1).optional(),
});

export type PidExtensionState = z.infer<typeof pidExtensionStateSchema>;

const PID_CORE_IDENTITY_FIELDS = [
  "given_name",
  "family_name",
  "tax_id_code",
  "birthdate",
  "place_of_birth",
] as const satisfies readonly (keyof PidIssuanceConfig)[];

/**
 * Projects validated `[issuance_pid]` config into {@link PidIdentityConfig}.
 * Returns `undefined` when `mode = none` (no PID identity simulation active).
 */
/**
 * Whether mock eID / MRTD simulation is active for this run.
 *
 * - Explicit `[issuance_pid].mock_mrtd_enabled` wins when present.
 * - Otherwise `true` when `mode` is `l2plus` or `l3`.
 */
export function isMockMrtdEnabled(
  issuancePid: PidIssuanceConfig | undefined,
): boolean {
  if (!issuancePid) {
    return false;
  }
  if (issuancePid.mock_mrtd_enabled !== undefined) {
    return issuancePid.mock_mrtd_enabled;
  }
  return issuancePid.mode !== "none";
}

/** Convenience wrapper over `config.issuance_pid`. */
export function isMockMrtdEnabledFromConfig(config: {
  issuance_pid?: PidIssuanceConfig;
}): boolean {
  return isMockMrtdEnabled(config.issuance_pid);
}

export function pidIdentityConfigFromIssuancePid(
  issuancePid: PidIssuanceConfig | undefined,
): PidIdentityConfig | undefined {
  if (!issuancePid || issuancePid.mode === "none") {
    return undefined;
  }

  for (const field of PID_CORE_IDENTITY_FIELDS) {
    if (!issuancePid[field]) {
      return undefined;
    }
  }

  return pidIdentityConfigSchema.parse({
    birthdate: issuancePid.birthdate,
    email: issuancePid.email,
    family_name: issuancePid.family_name,
    given_name: issuancePid.given_name,
    mrz: issuancePid.mrz,
    nationalities: issuancePid.nationalities,
    personal_administrative_number: issuancePid.personal_administrative_number,
    phone_number: issuancePid.phone_number,
    place_of_birth: issuancePid.place_of_birth,
    tax_id_code: issuancePid.tax_id_code,
  });
}
