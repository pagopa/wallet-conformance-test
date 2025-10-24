import { parse } from "ini";
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

import { loadCredentials } from "@/functions";
import { Config } from "@/types";
import { ValidationError } from "@pagopa/io-wallet-utils";

test("Mocked Credentials Validation", async () => {
  const textConfig = readFileSync("config.ini", "utf-8");
  const config = parse(textConfig) as Config;
  const types: string[] = [];

  for (const type in config.issuance.credentials.types) {
    const issuerHasType = config.issuance.credentials.types[type]?.find(
      (t) => t === config.issuance.url,
    );

    if (issuerHasType) types.push(type);
  }

  try {
    await loadCredentials(
      "tests/data/credentials",
      types,
    );
  } catch (e) {
    if (e instanceof ValidationError) {
        console.error("Schema validation failed");
        expect
          .soft(
            e.message.replace(": ", ":\n\t").replace(/,([A-Za-z])/g, "\n\t$1"),
          )
          .toBeNull();
        }
    else throw e;
  }
});
