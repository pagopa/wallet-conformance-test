import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createAndSaveKeys, createKeys } from "@/logic/jwk";

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
