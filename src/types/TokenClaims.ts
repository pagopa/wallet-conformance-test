import { z } from "zod";

export const tokenClaimsSchema = z.looseObject({
	jwks: z.object({
		keys: z.array(z.object({
			kty: z.string(),
			kid: z.string(),
			use: z.string().optional(),
			key_ops: z.array(z.string()).optional(),
			alg: z.string().optional(),
			x5u: z.string().optional(),
			x5c: z.string().optional(),
			x5t: z.string().optional(),
			'x5t#S256': z.string().optional()
		}))
	})
});

export type TokenClaims = z.infer<typeof tokenClaimsSchema>;
