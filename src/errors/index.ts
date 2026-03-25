export class CertificateExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateExpiredError";
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
