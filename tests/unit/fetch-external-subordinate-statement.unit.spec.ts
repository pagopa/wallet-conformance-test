import { afterEach, describe, expect, it, vi } from "vitest";

import type { Config } from "@/types";

import * as logic from "@/logic";
import { fetchExternalSubordinateStatement } from "@/trust-anchor/external-ta-registration";

const network: Config["network"] = {
  max_retries: 1,
  timeout: 5,
  user_agent: "test-agent/1.0",
  tls_reject_unauthorized: true,
};

const EXTERNAL_TA_URL = "https://ta.example.com";
const WP_BASE_URL = "https://wp.example.com";

function makeFetchMock(
  status: number,
  contentType: string,
  body: string,
): typeof fetch {
  return vi.fn().mockResolvedValue({
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "content-type" ? contentType : null,
    },
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(body),
  });
}

describe("fetchExternalSubordinateStatement – content-type validation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns the JWT body when content-type is application/entity-statement+jwt", async () => {
    const jwtBody = "eyJhbGciOiJFUzI1NiJ9.payload.sig";
    vi.stubGlobal(
      "fetch",
      makeFetchMock(200, "application/entity-statement+jwt", jwtBody),
    );

    const result = await fetchExternalSubordinateStatement(
      EXTERNAL_TA_URL,
      WP_BASE_URL,
      network,
    );

    expect(result).toBe(jwtBody);
  });

  it("returns the JWT body when content-type has charset suffix", async () => {
    const jwtBody = "eyJhbGciOiJFUzI1NiJ9.payload.sig";
    vi.stubGlobal(
      "fetch",
      makeFetchMock(
        200,
        "application/entity-statement+jwt; charset=utf-8",
        jwtBody,
      ),
    );

    const result = await fetchExternalSubordinateStatement(
      EXTERNAL_TA_URL,
      WP_BASE_URL,
      network,
    );

    expect(result).toBe(jwtBody);
  });

  it("throws a descriptive error when content-type is text/html (proxy error page)", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetchMock(200, "text/html; charset=utf-8", "<html>Error</html>"),
    );

    await expect(
      fetchExternalSubordinateStatement(EXTERNAL_TA_URL, WP_BASE_URL, network),
    ).rejects.toThrow(
      `External TA /fetch returned unexpected content-type 'text/html; charset=utf-8' for sub=${WP_BASE_URL}. Expected 'application/entity-statement+jwt'.`,
    );
  });

  it("throws a descriptive error when content-type is application/json", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetchMock(200, "application/json", '{"error":"not_found"}'),
    );

    await expect(
      fetchExternalSubordinateStatement(EXTERNAL_TA_URL, WP_BASE_URL, network),
    ).rejects.toThrow(
      `External TA /fetch returned unexpected content-type 'application/json' for sub=${WP_BASE_URL}. Expected 'application/entity-statement+jwt'.`,
    );
  });

  it("throws a descriptive error when content-type header is absent", async () => {
    vi.stubGlobal("fetch", makeFetchMock(200, "", "some body"));

    await expect(
      fetchExternalSubordinateStatement(EXTERNAL_TA_URL, WP_BASE_URL, network),
    ).rejects.toThrow(
      `External TA /fetch returned unexpected content-type '' for sub=${WP_BASE_URL}. Expected 'application/entity-statement+jwt'.`,
    );
  });

  it("throws on non-2xx HTTP status before reaching content-type check", async () => {
    vi.stubGlobal(
      "fetch",
      makeFetchMock(404, "application/entity-statement+jwt", ""),
    );

    await expect(
      fetchExternalSubordinateStatement(EXTERNAL_TA_URL, WP_BASE_URL, network),
    ).rejects.toThrow(
      `External TA /fetch returned HTTP 404 for sub=${WP_BASE_URL}`,
    );
  });
});

describe("fetchExternalSubordinateStatement – fetchWithRetries error propagation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("throws descriptive error on generic network failure", async () => {
    vi.spyOn(logic, "fetchWithRetries").mockRejectedValue(
      new Error("Request failed with no retries left: aborting"),
    );

    await expect(
      fetchExternalSubordinateStatement(EXTERNAL_TA_URL, WP_BASE_URL, network),
    ).rejects.toThrow(
      `External TA /fetch failed after ${network.max_retries} attempts for sub=${WP_BASE_URL}`,
    );
  });

  it("throws descriptive timeout error on TimeoutError", async () => {
    const timeoutError = Object.assign(
      new Error("Request timed out: aborting"),
      { name: "TimeoutError" },
    );
    vi.spyOn(logic, "fetchWithRetries").mockRejectedValue(timeoutError);

    await expect(
      fetchExternalSubordinateStatement(EXTERNAL_TA_URL, WP_BASE_URL, network),
    ).rejects.toThrow(
      `External TA /fetch timed out after ${network.timeout}s for sub=${WP_BASE_URL}`,
    );
  });
});
