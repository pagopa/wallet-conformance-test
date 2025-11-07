import { jsonWebKeySchema as JWK } from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

export const sdJwtHeaderSchema = z.object({
  alg: z.string(),
  kid: z.string(),
  trust_chain: z.array(z.string()).optional(),
  typ: z.literal("dc+sd-jwt"),
  vctm: z.array(z.string()).optional(),
  x5c: z.array(z.string()).optional(),
});

export const sdJwtPayloadSchema = z.object({
  _sd: z.array(z.string()),
  _sd_alg: z.literal("sha-256"), // .or(z.literal("sha-384")).or(z.literal("sha-512")).default("sha-256"),
  cnf: z.object({ jwk: JWK }),
  exp: z.number().int().nonnegative(),
  iat: z.number().int().nonnegative(),
  iss: z.string().url(),
  issuing_authority: z.string(),
  issuing_country: z.string().length(2).toUpperCase(),
  nbf: z.number().int().nonnegative().optional(),
  status: z
    .object({
      status_list: z
        .object({
          idx: z.number().int().nonnegative(),
          uri: z.string().url(),
        })
        .or(
          z.object({
            status_assertion: z.object({
              credential_hash_alg: z.string(),
            }),
          }),
        ),
    })
    .optional(),
  sub: z.string(),
  vct: z.string().regex(/urn:eudi:[^:]+:it:[0-9]+/),
  "vct#integrity": z.string(),
  verification: z
    .object({
      assurance_level: z.string(),
      evidence: z.array(
        z.object({
          attestation: z.object({
            date_of_issuing: z.date(),
            reference_number: z.number(),
            type: z.literal("digital_attestation"),
            voucher: z.object({
              organization: z.string(),
            }),
          }),
          time: z.number().int().nonnegative(),
          type: z.literal("vouch"),
        }),
      ),
      trust_framework: z.string(),
    })
    .optional(),
});

export const sdJwtSchema = z.object({
  encoded: z.string(),
  header: sdJwtHeaderSchema,
  payload: sdJwtPayloadSchema,
});

export type SdJwt = z.infer<typeof sdJwtSchema>;
export type SdJwtHeader = z.infer<typeof sdJwtHeaderSchema>;
export type SdJwtPayload = z.infer<typeof sdJwtPayloadSchema>;
