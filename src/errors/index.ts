export class CertificateExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateExpiredError";
  }
}
