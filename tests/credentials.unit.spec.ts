import { test } from "vitest";

import { parse } from "ini";
import { loadCredentials } from "@/functions";
import { readFileSync } from "node:fs";
import { Config } from "@/types";

test("Mocked Credentials Validation", () => {
        const textConfig = readFileSync("config.ini", "utf-8");
        const issuerKey = JSON.parse(
            readFileSync("tests/data/backup/issuer_jwk.pub", "utf-8")
        );
        const config = parse(textConfig) as Config;
        const types: string[] = []

        for (const type in config.issuance.credentials.types) {
            const issuerHasType = config.issuance.credentials.types[type]?.
                find(t => t === config.issuance.url)

            if (issuerHasType)
                types.push(type)
        }

        loadCredentials(
            "tests/data/credentials",
            types,
            issuerKey,
            "tests/data/certs/cert.pem"
        );
    }
);
