import { z } from "zod";

/**
 * Represents the configuration for the wallet conformance test.
 */
export const configSchema = z.object({
  issuance: z.object({
    credentials: z.object({
      types: z.record(z.string(), z.array(z.string())),
    }),
    url: z.string().url(),
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
  server: z.object({
    port: z.coerce.number(),
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
