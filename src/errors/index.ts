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

export class MissingFieldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MissingFieldError";
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
