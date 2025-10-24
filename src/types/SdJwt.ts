import { JWK } from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

export const sdJwtHeader = z.object({
  alg: z.string(),
  kid: z.string(),
  trust_chain: z.array(z.string()).optional(),
  typ: z.literal("dc+sd-jwt"),
  vctm: z.array(z.string()).optional(),
  x5c: z.string().optional(),
});

export const sdJwtPayload = z.object({
  _sd: z.array(z.string()),
  _sd_alg: z.string(),
  cnf: z.object({ jwk: JWK }),
  exp: z.number().int().nonnegative(),
  iat: z.number().int().nonnegative(),
  iss: z.string().url(),
  issuing_authority: z.string(),
  issuing_country: z.string().length(2).toUpperCase(),
  nbf: z.number().int().nonnegative().optional(),
  status: z
    .object({
      idx: z.number().int().nonnegative(),
      uri: z.string().url(),
    })
    .or(
      z.object({
        credential_hash_alg: z.string(),
      }),
    )
    .optional(),
  sub: z.string(),
  vct: z.string().url().startsWith("https"),
  "vct#integrity": z.string(),
  verification: z.object({
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
  }),
});

export const sdJwt = z.object({
  encoded: z.string(),
  header: sdJwtHeader,
  payload: sdJwtPayload,
});

export type SdJwt = z.infer<typeof sdJwt>;
export type SdJwtHeader = z.infer<typeof sdJwtHeader>;
export type SdJwtPayload = z.infer<typeof sdJwtPayload>;
