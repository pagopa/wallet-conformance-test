import { z } from "zod";

const configSchema = z.object({
	wallet: z.object({
		wallet_id: z.coerce.string(),
		wallet_name: z.coerce.string(),
		wallet_provider_base_url: z.coerce.string(),
		wallet_attestations_storage_path: z.coerce.string(),
		credentials_storage_path: z.coerce.string(),
		backup_storage_path: z.coerce.string()
	})
});

/**
 * Represents the configuration for the wallet conformance test.
 */
export type Config = z.infer<typeof configSchema>;
