import { z } from "zod";

const configSchema = z.object({
	wallet: z.object({
		wallet_id: z.coerce.string(),
		wallet_name: z.coerce.string(),
		wallet_provider_base_url: z.coerce.string(),
		wallet_attestations_storage_path: z.coerce.string(),
		credentials_storage_path: z.coerce.string(),
		backup_storage_path: z.coerce.string()
	}),
	trust: z.object({
		eidas_trusted_lists: z.coerce.string().optional(),
		ca_cert_path: z.coerce.string(),
		federation_trust_anchors: z.array(z.coerce.string()),
		federation_trust_anchors_jwks_path: z.coerce.string()
	}),
	issuance: z.object({
		url: z.coerce.string(),
		credentials: z.object({
			types: z.object({
				dc_sd_jwt_PersonIdentificationData: z.array(z.coerce.string()),
				dc_sd_jwt_mDL: z.array(z.coerce.string()),
				mso_mdoc_mDL: z.array(z.coerce.string()),
				dc_sd_jwt_EuropeanDisabilityCard: z.array(z.coerce.string())
			})
		})
	}),
	network: z.object({
		timeout: z.coerce.number(),
		max_retries: z.coerce.number(),
		user_agent: z.coerce.string()
	}),
	logging: z.object({
		log_level: z.coerce.string(),
		log_file: z.coerce.string(),
		log_format: z.coerce.string()
	})
});

export type Config = z.infer<typeof configSchema>
