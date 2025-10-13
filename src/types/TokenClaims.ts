import { z } from "zod";

export const tokenClaimsSchema = z.looseObject({
  jwks: z.object({
    keys: z.array(
      z.object({
        alg: z.string().optional(),
        key_ops: z.array(z.string()).optional(),
        kid: z.string(),
        kty: z.string(),
        use: z.string().optional(),
        x5c: z.string().optional(),
        x5t: z.string().optional(),
        "x5t#S256": z.string().optional(),
        x5u: z.string().optional(),
      }),
    ),
  }),
});

export type TokenClaims = z.infer<typeof tokenClaimsSchema>;
