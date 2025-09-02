import { z } from "zod";

/**
 * Represents the configuration for the wallet conformance test.
 */
export const configSchema = z.object({
  issuance: z.object({
    credentials: z.object({
      types: z.object({
        dc_sd_jwt_EuropeanDisabilityCard: z.array(z.coerce.string()),
        dc_sd_jwt_mDL: z.array(z.coerce.string()),
        dc_sd_jwt_PersonIdentificationData: z.array(z.coerce.string()),
        mso_mdoc_mDL: z.array(z.coerce.string()),
      }),
    }),
    url: z.coerce.string(),
  }),
  logging: z.object({
    log_file: z.coerce.string(),
    log_format: z.coerce.string(),
    log_level: z.coerce.string(),
  }),
  network: z.object({
    max_retries: z.coerce.number(),
    timeout: z.coerce.number(),
    user_agent: z.coerce.string(),
  }),
  trust: z.object({
    ca_cert_path: z.coerce.string(),
    eidas_trusted_lists: z.coerce.string().optional(),
    federation_trust_anchors: z.array(z.coerce.string()),
    federation_trust_anchors_jwks_path: z.coerce.string(),
  }),
  wallet: z.object({
    backup_storage_path: z.coerce.string(),
    credentials_storage_path: z.coerce.string(),
    wallet_attestations_storage_path: z.coerce.string(),
    wallet_id: z.coerce.string(),
    wallet_name: z.coerce.string(),
    wallet_provider_base_url: z.coerce.string(),
  }),
});

export type Config = z.infer<typeof configSchema>;
