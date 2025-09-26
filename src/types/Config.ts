import { z } from "zod";

export const configSchema = z.object({
  wallet: z.object({
    backup_storage_path: z.coerce.string(),
    credentials_storage_path: z.coerce.string(),
    wallet_attestations_storage_path: z.coerce.string(),
    wallet_id: z.coerce.string(),
    wallet_name: z.coerce.string(),
    wallet_provider_base_url: z.coerce.string(),
  }),
	trust: z.looseObject({
		ca_cert_path: z.string()
	}),
	issuance: z.object({
		url: z.string(),
		credentials: z.object({
			types: z.record(z.string(), z.array(z.string()))
		})
	})
});

/**
 * Represents the configuration for the wallet conformance test.
 */
export type Config = z.infer<typeof configSchema>;
