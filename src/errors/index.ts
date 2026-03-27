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

export class TrustChainExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrustChainExpiredError";
  }
}
