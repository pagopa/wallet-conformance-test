import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { z } from "zod";

import { parseItWalletSpecVersion } from "./version";

/**
 * Preprocessor that safely coerces INI/env string values to booleans.
 * `z.coerce.boolean()` is unsafe because JavaScript's `Boolean("false")` returns
 * `true` (any non-empty string is truthy), so an INI entry like
 * `tls_reject_unauthorized = false` would mistakenly be treated as `true`.
 * This helper explicitly maps "true"/"1" → true and "false"/"0" → false;
 * real boolean values pass through unchanged.
 */
const booleanFromString = (val: unknown): unknown => {
  if (typeof val === "string") {
    if (val === "true" || val === "1") return true;
    if (val === "false" || val === "0") return false;
  }
  return val;
};

/**
 * Represents the configuration for the wallet conformance test.
 */
export const configSchema = z.object({
  issuance: z.object({
    certificate_subject: z.string().optional(),
    credential_offer_uri: z
      .string()
      .url()
      .startsWith("https://")
      .or(z.string().startsWith("haip-vci://"))
      .or(z.string().startsWith("openid-credential-offer://"))
      .optional(),
    credential_types: z.array(z.string()).optional().default([]),
    save_credential: z
      .preprocess(booleanFromString, z.boolean())
      .optional()
      .default(false),
    tests_dir: z.string().default("./tests/issuance"),
    url: z.string().url(),
  }),
  logging: z.object({
    log_file: z.string(),
    log_file_format: z.string().optional(),
    log_format: z.string(),
    log_level: z.string(),
  }),
  network: z.object({
    max_retries: z.coerce.number().default(10),
    timeout: z.coerce.number().default(10),
    tls_reject_unauthorized: z
      .preprocess(booleanFromString, z.boolean())
      .optional()
      .default(true),
    user_agent: z.string().optional(),
  }),
  presentation: z.object({
    authorize_request_url: z.string().url(),
    tests_dir: z.string().default("./tests/presentation"),
    verifier: z.string().url().optional(),
  }),
  steps_mapping: z
    .object({
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
  server: z.object({
    port: z.coerce.number({
      required_error:
        "server.port is required. Please add a [server] section to your config.ini with 'port = <number>'. " +
        "If you previously set 'port' under [trust_anchor], move it to the new [server] section.",
      invalid_type_error:
        "server.port must be a valid port number. Please check your config.ini: set 'port = <number>' under [server]. " +
        "If you previously set 'port' under [trust_anchor], move it to the new [server] section.",
    }),
  }),
  trust: z.object({
    ca_cert_path: z.string(),
    certificate_subject: z.string().min(5),
    eidas_trusted_lists: z.array(z.string()).optional(),
    federation_trust_anchors: z.array(z.string()),
    federation_trust_anchors_jwks_path: z.string(),
  }),
  trust_anchor: z.object({
    external_ta_onboarding_url: z.string().url().optional(),
    external_ta_url: z.string().url().optional(),
  }),
  wallet: z.object({
    backup_storage_path: z.string(),
    credentials_storage_path: z.string(),
    mock_issuer: z.string().default("https://example.issuer.com"),
    wallet_attestations_storage_path: z.string(),
    wallet_id: z.string(),
    wallet_name: z.string(),
    wallet_provider_base_url: z.string().url(),
    wallet_version: z
      .string({
        required_error: `wallet_version is required. Admissible values: ${Object.values(ItWalletSpecsVersion).join(", ")}`,
      })
      .refine(
        (version) => parseItWalletSpecVersion(version),
        `Invalid wallet_version. Admissible values: ${Object.values(ItWalletSpecsVersion).join(", ")}`,
      )
      .transform((version) => version as ItWalletSpecsVersion),
  }),
});

export type Config = z.infer<typeof configSchema>;
