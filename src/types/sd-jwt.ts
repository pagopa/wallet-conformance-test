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

export const sdJwtPayload = z.looseObject({
  _sd: z.array(z.string()),
  _sd_alg: z.string(),
  cnf: z.object({ jwk: JWK }),
  exp: z.uint32(),
  iat: z.uint32(),
  iss: z.url(),
  issuing_authority: z.string(),
  issuing_country: z.string().length(2).uppercase(),
  nbf: z.uint32().optional(),
  status: z
    .object({
      idx: z.uint32(),
      uri: z.url(),
    })
    .or(
      z.object({
        credential_hash_alg: z.string(),
      }),
    )
    .optional(),
  sub: z.string(),
  vct: z.url({ protocol: /https/ }),
  "vct#integrity": z.string(),
  verification: z.object({
    assurance_level: z.string(),
    evidence: z.array(
      z.object({
        attestation: z.object({
          date_of_issuing: z.date(),
          reference_number: z.number(),
          type: z.literal("digital_attestation"),
          voucher: z.looseObject({
            organization: z.string(),
          }),
        }),
        time: z.uint32(),
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
