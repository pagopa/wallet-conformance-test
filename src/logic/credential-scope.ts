/**
 * Returns the scope to request for the given Credential Configurations: the
 * space-separated `scope` values the issuer advertises for them in
 * `credential_configurations_supported`. The IT-Wallet Request Object makes
 * `scope` REQUIRED and says the wallet MUST use the advertised value.
 *
 * @param credentialConfigurationIds - The requested configuration ids
 * @param credentialConfigsSupported - The issuer's `credential_configurations_supported`
 * @returns The scope, or undefined when no requested configuration advertises one
 */
export function resolveCredentialScope(
  credentialConfigurationIds: string[],
  credentialConfigsSupported: Record<string, { scope?: string }> | undefined,
): string | undefined {
  const scopes = credentialConfigurationIds
    .map((id) => credentialConfigsSupported?.[id]?.scope)
    .filter(
      (scope): scope is string => typeof scope === "string" && scope.length > 0,
    );
  return scopes.length > 0 ? scopes.join(" ") : undefined;
}
