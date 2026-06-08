export class AttestationExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationExpiredError";
  }
}

export class CertificateExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateExpiredError";
  }
}

export class CredentialNamespaceNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialNamespaceNotFoundError";
  }
}

/** OpenID4VCI credential configuration id for Person Identification Data (PID). */
export const PID_CREDENTIAL_CONFIGURATION_ID =
  "dc_sd_jwt_PersonIdentificationData" as const;

export class MissingFieldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MissingFieldError";
  }
}

/**
 * Thrown when `issuance.credential_types[]` requests PID issuance but
 * `[issuance_pid].mode` is `none` (FR-3).
 */
export class PidIssuanceModeNotConfiguredError extends Error {
  readonly code = "PID_ISSUANCE_MODE_NOT_CONFIGURED";
  readonly credentialConfigurationId = PID_CREDENTIAL_CONFIGURATION_ID;

  constructor() {
    super(
      `credential_types[] includes '${PID_CREDENTIAL_CONFIGURATION_ID}' but ` +
        `[issuance_pid].mode is 'none'. ` +
        `Fix: set [issuance_pid] mode = l3 or l2plus in config.ini, ` +
        `or remove '${PID_CREDENTIAL_CONFIGURATION_ID}' from credential_types[] ` +
        `for standard (Q)EAA issuance tests.`,
    );
    this.name = "PidIssuanceModeNotConfiguredError";
  }
}
export class StatusListTokenCreationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StatusListTokenCreationError";
  }
}

export class TrustChainExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrustChainExpiredError";
  }
}
