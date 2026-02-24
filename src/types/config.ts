import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { z } from "zod";

import { parseItWalletSpecVersion } from "./version";

/**
 * Represents the configuration for the wallet conformance test.
 */
export const configSchema = z.object({
  issuance: z.object({
    credential_offer_uri: z
      .string()
      .url()
      .startsWith("https://")
      .or(z.string().startsWith("haip-vci://"))
      .or(z.string().startsWith("openid-credential-offer://"))
      .optional(),
    credential_types: z.array(z.string()).optional().default([]),
    save_credential: z.coerce.boolean().optional().default(false),
    tests_dir: z.string().default("./tests/issuance"),
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
  presentation: z.object({
    authorize_request_url: z.string().url(),
    tests_dir: z.string().default("./tests/presentation"),
    verifier: z.string().url().optional(),
  }),
  steps_mapping: z
    .object({
      default_steps_dir: z.string().optional(),
      mapping: z.record(z.string(), z.string()).optional().default({}),
    })
    .optional()
    .default({ mapping: {} }),
  testing: z
    .object({
      custom_step_pattern: z.string().default("**/*.ts"),
      spec_pattern: z.string().default("**/*.spec.ts"),
    })
    .optional()
    .default({
      custom_step_pattern: "**/*.ts",
      spec_pattern: "**/*.spec.ts",
    }),
  trust: z.object({
    ca_cert_path: z.string(),
    certificate_subject: z.string(),
    eidas_trusted_lists: z.array(z.string()).optional(),
    federation_trust_anchors: z.array(z.string()),
    federation_trust_anchors_jwks_path: z.string(),
  }),
  trust_anchor: z.object({
    port: z.coerce.number(),
  }),
  wallet: z.object({
    backup_storage_path: z.string(),
    credentials_storage_path: z.string(),
    wallet_attestations_storage_path: z.string(),
    wallet_id: z.string(),
    wallet_name: z.string(),
    wallet_provider_base_url: z.string(),
    wallet_version: z
      .string()
      .optional()
      .refine(
        (version) => !version || parseItWalletSpecVersion(version),
        `Admissible values for wallet version are ${Object.values(ItWalletSpecsVersion)}`,
      )
      .transform((version) => version as ItWalletSpecsVersion | undefined),
  }),
});

export type Config = z.infer<typeof configSchema>;
