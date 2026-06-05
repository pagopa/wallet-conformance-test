import { z } from "zod";

/** JOSE `typ` for `mrtd_validation_jwt` and MRTD Proof JWT (L2+ spec §12.1.3.5.3.5–7). */
export const MRTD_VALIDATION_JWT_TYP = "mrtd-ias+jwt";

/** JOSE `typ` for the MRTD Proof JWT in `challenge_info` (L2+ spec §12.1/12.2). */
export const MRTD_PROOF_JWT_TYP = MRTD_VALIDATION_JWT_TYP;

/** JOSE `typ` for the MRTD PoP init response JWT (FR / annex §5.1 L2+). */
export const MRTD_IAS_POP_JWT_TYP = "mrtd-ias-pop+jwt";

export const mrtdProofJwtPayloadSchema = z.object({
  aud: z.string().min(1),
  htm: z.literal("POST"),
  htu: z.url(),
  iss: z.string().min(1).optional(),
  mrtd_auth_session: z.string().min(1),
  mrtd_pop_jwt_nonce: z.string().min(1),
  state: z.string().min(1),
  status: z.literal("require_interaction"),
  type: z.literal("mrtd+ias"),
});

export type MrtdProofJwtPayload = z.infer<typeof mrtdProofJwtPayloadSchema>;

export const mrtdIasPopJwtPayloadSchema = z.object({
  challenge: z.string().min(1),
  htm: z.literal("POST"),
  htu: z.string().url(),
  mrtd_pop_nonce: z.string().min(1),
  mrz: z.string().min(1).optional(),
});

export type MrtdIasPopJwtPayload = z.infer<typeof mrtdIasPopJwtPayloadSchema>;

export const mrtdPopVerifyResponseSchema = z.object({
  mrtd_val_pop_nonce: z.string().min(1),
  redirect_uri: z.string().url(),
  status: z.literal("require_interaction"),
  type: z.literal("redirect_to_web"),
});

export type MrtdPopVerifyResponse = z.infer<typeof mrtdPopVerifyResponseSchema>;

const jwkObjectSchema = z
  .object({
    kty: z.string().min(1),
  })
  .passthrough();

export const mrtdValidationJwtMrtdBlockSchema = z.object({
  dg1: z.string().min(1),
  dg11: z.string().min(1),
  sod_mrtd: z.string().min(1),
});

export const mrtdValidationJwtIasBlockSchema = z.object({
  challenge_signed: z.string().min(1),
  ias_pk: jwkObjectSchema,
  sod_ias: z.string().min(1),
});

/**
 * Normative payload for `mrtd_validation_jwt` (L2+ spec §12.1.3.5.3.5–7, pre-signing).
 * Binary MRTD fields are base64url-encoded strings.
 */
export const mrtdValidationJwtClaimsSchema = z.object({
  aud: z.string().min(1),
  document_type: z.literal("cie"),
  ias: mrtdValidationJwtIasBlockSchema,
  iss: z.string().min(1),
  mrtd: mrtdValidationJwtMrtdBlockSchema,
});

export type MrtdValidationJwtClaims = z.infer<
  typeof mrtdValidationJwtClaimsSchema
>;

export type MrtdValidationJwtIasBlock = z.infer<
  typeof mrtdValidationJwtIasBlockSchema
>;

export type MrtdValidationJwtMrtdBlock = z.infer<
  typeof mrtdValidationJwtMrtdBlockSchema
>;

export const mockIdTokenPayloadSchema = z
  .object({
    acr: z.string().min(1),
    birthdate: z.string().min(1),
    email: z.email().optional(),
    family_name: z.string().min(1),
    given_name: z.string().min(1),
    iss: z.string().min(1).optional(),
    phone_number: z.string().min(1).optional(),
    sub: z.string().min(1),
    tax_id_code: z.string().min(1),
  })
  .passthrough();

export type MockIdTokenPayload = z.infer<typeof mockIdTokenPayloadSchema>;

export function parseMrtdIasPopJwtPayload(
  payload: unknown,
): MrtdIasPopJwtPayload {
  return mrtdIasPopJwtPayloadSchema.parse(payload);
}

export function parseMrtdPopVerifyResponse(
  body: unknown,
): MrtdPopVerifyResponse {
  return mrtdPopVerifyResponseSchema.parse(body);
}

export function parseMrtdProofJwtPayload(
  payload: unknown,
): MrtdProofJwtPayload {
  return mrtdProofJwtPayloadSchema.parse(payload);
}

export function parseMrtdValidationJwtClaims(
  payload: unknown,
): MrtdValidationJwtClaims {
  return mrtdValidationJwtClaimsSchema.parse(payload);
}
