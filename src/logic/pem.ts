import * as x509 from "@peculiar/x509";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { KeyPair } from "@/types";

import { createKeys } from "./jwk";
import { CLOCK_SKEW_TOLERANCE_MS, ensureDir, VALIDITY_MS } from "./utils";

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface CertificateResult {
  /** DER-encoded certificate, base64-encoded — suitable for x5c arrays. */
  certDerBase64: string;
  /** The X.509 certificate object. */
  certificate: x509.X509Certificate;
  /** Absolute path of the persisted certificate file (set by loadOrCreate). */
  certPath?: string;
  /** The certificate in PEM format. */
  certPem: string;
  /** The key pair associated with the certificate (when provided or generated). */
  keyPair?: KeyPair;
  /** Absolute path of the persisted key file (set by loadOrCreate with generated key). */
  keyPath?: string;
  /** Private key in PKCS#8 PEM format (set when key is generated). */
  keyPem?: string;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

export class CertificateBuilder {
  private _caPathLen?: number;
  private _extensions: x509.Extension[] = [];
  private _generateKey = false;
  private _isCA = false;
  private _issuerCert?: x509.X509Certificate;
  private _issuerKeyPair?: KeyPair;
  private _keyPair?: KeyPair;
  private _subject?: string;
  private _validityMs = VALIDITY_MS;

  /**
   * Create the certificate in memory without persisting to disk.
   */
  async create(): Promise<CertificateResult> {
    const subject = this._subject;
    if (!subject) throw new Error("Subject is required: call withSubject()");

    const keyPair = this._generateKey ? await createKeys() : this._keyPair;
    if (!keyPair)
      throw new Error(
        "Key pair is required: call withKeyPair() or withGeneratedKey()",
      );

    const certificate =
      this._issuerCert && this._issuerKeyPair
        ? await createCertificateIssuerSigned(
            keyPair,
            subject,
            this._issuerCert,
            this._issuerKeyPair.privateKey,
            this._extensions,
            this._isCA,
            this._caPathLen,
            this._validityMs,
          )
        : this._issuerKeyPair
          ? await createCertificateSelfIssued(
              keyPair,
              subject,
              this._issuerKeyPair,
              this._extensions,
              this._isCA,
              this._caPathLen,
              this._validityMs,
            )
          : await createCertificateSelfSigned(
              keyPair,
              subject,
              this._extensions,
              this._isCA,
              this._caPathLen,
              this._validityMs,
            );

    const certPem = certificate.toString("pem");
    const certDerBase64 = Buffer.from(certificate.rawData).toString("base64");

    let keyPem: string | undefined;
    if (this._generateKey) {
      const privateKey = await crypto.subtle.importKey(
        "jwk",
        keyPair.privateKey,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"],
      );
      keyPem = await privateKeyToPem(privateKey);
    }

    return { certDerBase64, certificate, certPem, keyPair, keyPem };
  }

  /**
   * Load the certificate from disk. If not found or expired, create and persist
   * it automatically.
   *
   * When {@link withGeneratedKey} is active, files are named
   * `${fileName}.cert.pem` and `${fileName}.key.pem`.
   * Otherwise the certificate file is stored as `${fileName}` (no extension added).
   */
  async loadOrCreate(
    dir: string,
    fileName: string,
  ): Promise<CertificateResult> {
    const dirCreated = ensureDir(dir);

    if (!dirCreated) {
      const loaded = this._generateKey
        ? this.tryLoadWithKey(dir, fileName)
        : this.tryLoadCertOnly(dir, fileName);

      if (loaded) return loaded;
    }

    const result = await this.create();

    if (this._generateKey) {
      mkdirSync(dir, { recursive: true });
      const certPath = path.resolve(path.join(dir, `${fileName}.cert.pem`));
      const keyPath = path.resolve(path.join(dir, `${fileName}.key.pem`));
      writeFileSync(certPath, result.certPem);
      writeFileSync(keyPath, result.keyPem!, { mode: 0o600 });
      return { ...result, certPath, keyPath };
    }

    const certPath = path.resolve(path.join(dir, fileName));
    writeFileSync(certPath, result.certPem);
    return { ...result, certPath };
  }

  /**
   * Mark the certificate as self-issued (issuer DN = subject DN).
   *
   * - No argument: the subject key pair also signs the certificate (truly self-signed).
   * - With `signerKeyPair`: the certificate is signed by `signerKeyPair` while the
   *   public key in the certificate comes from {@link withKeyPair}. This produces a
   *   self-issued Protocol Certificate per IT-Wallet §6.14.2 — the federation entity
   *   key (Key A) certifies a separate protocol key (Key B).
   */
  selfIssued(signerKeyPair?: KeyPair): this {
    this._issuerCert = undefined;
    this._issuerKeyPair = signerKeyPair;
    return this;
  }

  /** Sign the certificate with an issuer (CA-signed). */
  signedBy(
    issuerCertificate: x509.X509Certificate,
    issuerKeyPair: KeyPair,
  ): this {
    this._issuerCert = issuerCertificate;
    this._issuerKeyPair = issuerKeyPair;
    return this;
  }

  /** Mark this certificate as a CA (BasicConstraints cA=TRUE, KeyUsage keyCertSign|cRLSign). */
  withCaCapability(pathLen?: number): this {
    this._isCA = true;
    this._caPathLen = pathLen;
    return this;
  }

  /** Append extra X.509 extensions to the certificate. */
  withExtensions(extensions: x509.Extension[]): this {
    this._extensions = extensions;
    return this;
  }

  /** Auto-generate a new ECDSA P-256 key pair. Mutually exclusive with withKeyPair(). */
  withGeneratedKey(): this {
    this._generateKey = true;
    this._keyPair = undefined;
    return this;
  }

  /** Provide an existing key pair. Mutually exclusive with withGeneratedKey(). */
  withKeyPair(keyPair: KeyPair): this {
    this._keyPair = keyPair;
    this._generateKey = false;
    return this;
  }

  /** Set the subject (CN) for the certificate. */
  withSubject(subject: string): this {
    this._subject = subject;
    return this;
  }

  /** Override the certificate validity window (default: VALIDITY_MS = 1 year). */
  withValidity(ms: number): this {
    this._validityMs = ms;
    return this;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private tryLoadCertOnly(
    dir: string,
    fileName: string,
  ): CertificateResult | undefined {
    const filePath = path.resolve(path.join(dir, fileName));
    if (!existsSync(filePath)) return undefined;

    try {
      const certPem = readFileSync(filePath, "utf-8");
      const certificate = new x509.X509Certificate(certPem);
      if (hasX509CertificateExpired(certificate)) {
        rmSync(filePath);
        return undefined;
      }
      const certDerBase64 = Buffer.from(certificate.rawData).toString("base64");
      return {
        certDerBase64,
        certificate,
        certPath: filePath,
        certPem,
        keyPair: this._keyPair,
      };
    } catch {
      return undefined;
    }
  }

  private tryLoadWithKey(
    dir: string,
    baseName: string,
  ): CertificateResult | undefined {
    const certPath = path.resolve(path.join(dir, `${baseName}.cert.pem`));
    const keyPath = path.resolve(path.join(dir, `${baseName}.key.pem`));
    if (!existsSync(certPath) || !existsSync(keyPath)) return undefined;

    try {
      const certPem = readFileSync(certPath, "utf-8");
      const keyPem = readFileSync(keyPath, "utf-8");
      const certificate = new x509.X509Certificate(certPem);
      if (hasX509CertificateExpired(certificate)) {
        rmSync(certPath);
        rmSync(keyPath);
        return undefined;
      }
      const certDerBase64 = Buffer.from(certificate.rawData).toString("base64");
      return {
        certDerBase64,
        certificate,
        certPath,
        certPem,
        keyPath,
        keyPem,
      };
    } catch {
      return undefined;
    }
  }
}

// ---------------------------------------------------------------------------
// Low-level certificate creation (used by CertificateBuilder)
// ---------------------------------------------------------------------------

export function hasX509CertificateExpired(x5c: string | x509.X509Certificate) {
  const certificate =
    typeof x5c === "string" ? new x509.X509Certificate(x5c) : x5c;
  return certificate.notAfter.getTime() < Date.now() - CLOCK_SKEW_TOLERANCE_MS;
}

export async function loadCertificate(
  certPath: string,
  filename: string,
  keyPair: KeyPair,
  subject: string,
): Promise<string> {
  const result = await new CertificateBuilder()
    .withSubject(subject)
    .withKeyPair(keyPair)
    .selfIssued()
    .loadOrCreate(certPath, filename);
  return result.certDerBase64;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

export async function loadOrCreateCertificateWithKey(
  dir: string,
  baseName: string,
  subject: string,
  extraExtensions: x509.Extension[] = [],
): Promise<{
  certPath: string;
  certPem: string;
  keyPath: string;
  keyPem: string;
}> {
  const result = await new CertificateBuilder()
    .withSubject(subject)
    .withGeneratedKey()
    .selfIssued()
    .withExtensions(extraExtensions)
    .loadOrCreate(dir, baseName);
  return {
    certPath: result.certPath!,
    certPem: result.certPem,
    keyPath: result.keyPath!,
    keyPem: result.keyPem!,
  };
}

async function createCertificateIssuerSigned(
  keyPair: KeyPair,
  subject: string,
  issuerCertificate: x509.X509Certificate,
  issuerPrivateKey: JsonWebKey,
  extraExtensions: x509.Extension[] = [],
  isCA = false,
  caPathLen?: number,
  validityMs = VALIDITY_MS,
): Promise<x509.X509Certificate> {
  const signingAlgorithm = {
    hash: "SHA-256",
    name: "ECDSA",
    namedCurve: "P-256",
  };

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  const signingKey = await crypto.subtle.importKey(
    "jwk",
    issuerPrivateKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + validityMs);

  const cert = await x509.X509CertificateGenerator.create({
    extensions: [
      new x509.BasicConstraintsExtension(
        isCA,
        isCA ? caPathLen : undefined,
        true,
      ),
      new x509.KeyUsagesExtension(
        isCA
          ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign
          : x509.KeyUsageFlags.digitalSignature,
        true,
      ),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(
        issuerCertificate,
        false,
      ),
      ...extraExtensions,
    ],
    issuer: issuerCertificate.subject,
    notAfter,
    notBefore,
    publicKey,
    serialNumber: crypto.randomUUID().replace(/-/g, ""),
    signingAlgorithm,
    signingKey,
    subject,
  });

  return cert;
}

// Self-issued: issuer DN = subject DN, signed by a (potentially different) key pair.
async function createCertificateSelfIssued(
  keyPair: KeyPair,
  subject: string,
  signerKeyPair: KeyPair,
  extraExtensions: x509.Extension[] = [],
  isCA = false,
  caPathLen?: number,
  validityMs = VALIDITY_MS,
): Promise<x509.X509Certificate> {
  const signingAlgorithm = {
    hash: "SHA-256",
    name: "ECDSA",
    namedCurve: "P-256",
  };

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const signerPublicKey = await crypto.subtle.importKey(
    "jwk",
    signerKeyPair.publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    signerKeyPair.privateKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + validityMs);

  return x509.X509CertificateGenerator.create({
    extensions: [
      new x509.BasicConstraintsExtension(
        isCA,
        isCA ? caPathLen : undefined,
        true,
      ),
      new x509.KeyUsagesExtension(
        isCA
          ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign
          : x509.KeyUsageFlags.digitalSignature,
        true,
      ),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(signerPublicKey),
      ...extraExtensions,
    ],
    issuer: subject,
    notAfter,
    notBefore,
    publicKey,
    serialNumber: crypto.randomUUID().replace(/-/g, ""),
    signingAlgorithm,
    signingKey,
    subject,
  });
}

// ---------------------------------------------------------------------------
// Legacy wrappers — delegate to CertificateBuilder for backward compatibility.
// Prefer CertificateBuilder directly in new code.
// ---------------------------------------------------------------------------

async function createCertificateSelfSigned(
  keyPair: KeyPair,
  subject: string,
  extraExtensions: x509.Extension[] = [],
  isCA = false,
  caPathLen?: number,
  validityMs = VALIDITY_MS,
): Promise<x509.X509Certificate> {
  const signingAlgorithm = {
    hash: "SHA-256",
    name: "ECDSA",
    namedCurve: "P-256",
  };

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.privateKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  const keys = { privateKey, publicKey };

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + validityMs);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    extensions: [
      new x509.BasicConstraintsExtension(
        isCA,
        isCA ? caPathLen : undefined,
        true,
      ),
      new x509.KeyUsagesExtension(
        isCA
          ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign
          : x509.KeyUsageFlags.digitalSignature,
        true,
      ),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      ...extraExtensions,
    ],
    keys,
    name: subject,
    notAfter,
    notBefore,
    signingAlgorithm,
  });

  return cert;
}

async function privateKeyToPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("pkcs8", key);
  const b64 = Buffer.from(exported).toString("base64");
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`;
}
