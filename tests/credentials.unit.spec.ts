import { test } from "vitest";

import { parse } from "ini";
import { loadCredentials } from "@/functions";
import { readFileSync } from "node:fs";
import { Config } from "@/types";

test("Mocked Credentials Validation", () => {
        const textConfig = readFileSync("config.ini", "utf-8");
        const config = parse(textConfig) as Config;
        const types: string[] = []

        for (const type in config) {
            const issuerHasType = config.issuance.credentials.types[type]?.
                find(t => t === config.issuance.url)

            if (issuerHasType)
                types.push(type)
        }

        loadCredentials(
            "data/credentials",
            types,
            publicKey,
            config.trust.ca_cert_path
        );
    }
);
