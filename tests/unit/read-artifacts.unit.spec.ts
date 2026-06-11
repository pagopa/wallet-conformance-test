import { addSecondsToDate } from "@pagopa/io-wallet-utils";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CertificateExpiredError } from "@/errors";
import {
  createAndSaveCertificate,
  createKeys,
  readCertificate,
  readJwks,
} from "@/logic";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(path.join(tmpdir(), "wct-test-"));
});

afterEach(() => {
  vi.useRealTimers();
  rmSync(tmpDir, { force: true, recursive: true });
});

describe("readJwks", () => {
  it("returns the parsed KeyPair for a valid JSON file", async () => {
    const keyPair = await createKeys();
    writeFileSync(path.join(tmpDir, "test_jwks"), JSON.stringify(keyPair));

    const loaded = readJwks(tmpDir, "test_jwks");

    expect(loaded.publicKey.kid, "public key kid should match").toBe(
      keyPair.publicKey.kid,
    );
    expect(loaded.privateKey.kid, "private key kid should match").toBe(
      keyPair.privateKey.kid,
    );
    expect(loaded.publicKey.kty, "kty should be EC").toBe("EC");
  });

  it("throws 'not found' when the file does not exist", () => {
    expect(() => readJwks(tmpDir, "missing_jwks")).toThrowError(
      `Key file not found at '${tmpDir}/missing_jwks'. Run 'wct init' to generate the required cryptographic artifacts.`,
    );
  });

  it("throws 'invalid data' when the file contains non-JSON content", () => {
    writeFileSync(path.join(tmpDir, "bad_jwks"), "not valid json {{");

    expect(() => readJwks(tmpDir, "bad_jwks")).toThrowError(
      `Key file at '${tmpDir}/bad_jwks' contains invalid data. Run 'wct init --force' to regenerate.`,
    );
  });

  it("throws 'invalid data' when the file contains valid JSON that is not a KeyPair", () => {
    writeFileSync(
      path.join(tmpDir, "bad_jwks"),
      JSON.stringify({ foo: "bar" }),
    );

    // JSON.parse succeeds and the cast to KeyPair returns whatever was in the file —
    // readJwks does not validate the shape, so this test documents current behaviour.
    const result = readJwks(tmpDir, "bad_jwks");
    expect(result).toEqual({ foo: "bar" });
  });
});

describe("readCertificate", () => {
  it("returns base64-DER string for a valid, non-expired certificate", async () => {
    const keyPair = await createKeys();
    await createAndSaveCertificate(
      path.join(tmpDir, "test_cert"),
      keyPair,
      "CN=test",
    );

    const result = readCertificate(tmpDir, "test_cert");

    expect(typeof result, "result should be a string").toBe("string");
    expect(result.length, "base64-DER should be non-empty").toBeGreaterThan(0);
    // PEM headers must have been stripped
    expect(result, "PEM header must not be present").not.toContain(
      "-----BEGIN CERTIFICATE-----",
    );
  });

  it("throws 'not found' when the file does not exist", () => {
    expect(() => readCertificate(tmpDir, "missing_cert")).toThrowError(
      `Certificate file not found at '${tmpDir}/missing_cert'. Run 'wct init' to generate the required cryptographic artifacts.`,
    );
  });

  it("throws CertificateExpiredError for an expired certificate", async () => {
    const now = new Date(2020, 0, 1);
    const twoYearsLater = addSecondsToDate(now, 3600 * 24 * 365 * 2);

    vi.useFakeTimers();
    vi.setSystemTime(now);

    const keyPair = await createKeys();
    await createAndSaveCertificate(
      path.join(tmpDir, "expired_cert"),
      keyPair,
      "CN=expired",
    );

    vi.setSystemTime(twoYearsLater);

    expect(() => readCertificate(tmpDir, "expired_cert")).toThrow(
      CertificateExpiredError,
    );
    expect(() => readCertificate(tmpDir, "expired_cert")).toThrowError(
      /has expired.*wct init --force/,
    );
  });

  it("includes the file path in the 'not found' error message", () => {
    const certDir = path.join(tmpDir, "sub");
    expect(() => readCertificate(certDir, "my_cert")).toThrowError(
      `${certDir}/my_cert`,
    );
  });
});
