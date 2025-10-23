import { z } from "zod";

/**
 * Represents the configuration for the wallet conformance test.
 */
export const configSchema = z.object({
  issuance: z.object({
    credentials: z.object({
      types: z.object({
        dc_sd_jwt_EuropeanDisabilityCard: z.array(z.string()),
        dc_sd_jwt_mDL: z.array(z.string()),
        dc_sd_jwt_PersonIdentificationData: z.array(z.string()),
        mso_mdoc_mDL: z.array(z.string()),
      }),
    }),
    url: z.string(),
  }),
  logging: z.object({
    log_file: z.string(),
    log_format: z.string(),
    log_level: z.string(),
  }),
  network: z.object({
    max_retries: z.coerce.number(),
    timeout: z.coerce.number(),
    user_agent: z.string(),
  }),
  trust: z.object({
    ca_cert_path: z.string(),
    eidas_trusted_lists: z.array(z.string()).optional(),
    federation_trust_anchors: z.array(z.string()),
    federation_trust_anchors_jwks_path: z.string(),
  }),
  wallet: z.object({
    backup_storage_path: z.string(),
    credentials_storage_path: z.string(),
    wallet_attestations_storage_path: z.string(),
    wallet_id: z.string(),
    wallet_name: z.string(),
    wallet_provider_base_url: z.string(),
  }),
});

export type Config = z.infer<typeof configSchema>;
