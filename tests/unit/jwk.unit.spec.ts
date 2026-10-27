import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createAndSaveKeys, createKeys, jwkFromSigner } from "@/logic/jwk";
import { createCertificate } from "@/logic/pem";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("JWK generation", () => {
  it("includes alg by default", async () => {
    const keyPair = await createKeys();

    expect(keyPair.privateKey.alg).toBe("ES256");
    expect(keyPair.publicKey.alg).toBe("ES256");
  });

  it("omits alg when generating credential binding keys", async () => {
    const directory = mkdtempSync(path.join(tmpdir(), "wct-jwk-"));
    temporaryDirectories.push(directory);
    const filePath = path.join(directory, "credential_jwks");

    const keyPair = await createAndSaveKeys(filePath, {
      includeAlgorithm: false,
    });
    const savedKeyPair = JSON.parse(
      readFileSync(filePath, "utf8"),
    ) as typeof keyPair;

    expect(keyPair.privateKey).not.toHaveProperty("alg");
    expect(keyPair.publicKey).not.toHaveProperty("alg");
    expect(savedKeyPair.privateKey).not.toHaveProperty("alg");
    expect(savedKeyPair.publicKey).not.toHaveProperty("alg");
  });
});

describe("jwkFromSigner with x5c", () => {
  it("falls back to the JWK thumbprint when the header has no kid", async () => {
    const keyPair = await createKeys();
    const cert = await createCertificate(keyPair, "CN=rp.example.org");
    const x5c = [Buffer.from(cert.rawData).toString("base64")];

    const jwk = await jwkFromSigner({ alg: "ES256", method: "x5c", x5c });

    expect(jwk.kid).toBe(keyPair.publicKey.kid);
  });
});
