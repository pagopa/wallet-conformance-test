import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { isMainModule } from "@/logic/entrypoint";

const originalArgv = [...process.argv];

afterEach(() => {
  process.argv = [...originalArgv];
});

describe("isMainModule", () => {
  it("detects the current ESM entrypoint", () => {
    const entrypoint = path.join(process.cwd(), "src/servers/ta-server.ts");
    process.argv[1] = entrypoint;

    expect(isMainModule(pathToFileURL(entrypoint).href)).toBe(true);
  });

  it("returns false for imported modules", () => {
    process.argv[1] = path.join(process.cwd(), "tests/global-setup.ts");

    expect(
      isMainModule(
        pathToFileURL(path.join(process.cwd(), "src/servers/ta-server.ts"))
          .href,
      ),
    ).toBe(false);
  });
});
