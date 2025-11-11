import { ValidationError } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

import { loadCredentials } from "@/functions";
import { Config } from "@/types";

test("Mocked Credentials Validation", async () => {
  const textConfig = readFileSync("config.ini", "utf-8");
  const config = parse(textConfig) as Config;
  const types: string[] = [];

  for (const type in config.issuance.credentials.types) {
    if (!type) continue;

    const issuerHasType = config.issuance.credentials.types[type]?.find(
      (t) => t === config.issuance.url,
    );

    if (issuerHasType) types.push(type);
  }

  try {
    await loadCredentials("tests/data/credentials", types, console.error);
  } catch (e) {
    if (e instanceof ValidationError) {
      const msg = e.message
        .replace(": ", ":\n\t")
        .replace(/,([A-Za-z])/g, "\n\t$1");
      expect.fail(`Schema validation failed: ${msg}`);
    } else throw e;
  }
});
