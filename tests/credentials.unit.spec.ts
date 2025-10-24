import { ValidationError } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

import { loadCredentials } from "@/functions";
import { Config } from "@/types";

test("Mocked Credentials Validation", async () => {
  const textConfig = readFileSync("config.ini", "utf-8");
  const issuerKey = JSON.parse(
    readFileSync("tests/data/backup/issuer_jwk.pub", "utf-8"),
  );
  const config = parse(textConfig) as Config;
  const types: string[] = [];

  for (const type in config.issuance.credentials.types) {
    if (!config.issuance.credentials.types[type]) continue;

    if (
      config.issuance.credentials.types[type].find(
        (t) => t === config.issuance.url,
      )
    )
      types.push(type);
  }

  try {
    await loadCredentials(
      "tests/data/credentials",
      types,
      issuerKey,
      // "tests/data/certs/cert.pem",
    );
  } catch (e) {
    if (e instanceof ValidationError) {
      console.error("Schema validation failed");
      expect
        .soft(
          e.message.replace(": ", ":\n\t").replace(/,([A-Za-z])/g, "\n\t$1"),
        )
        .toBeNull();
    } else throw e;
  }
});
