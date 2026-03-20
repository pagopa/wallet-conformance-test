import { StatusList } from "@sd-jwt/jwt-status-list";
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { describe, expect, it, vi } from "vitest";

import * as utils from "@/logic/utils";
import { createStatusListToken } from "@/logic/status-list";
import { loadConfigWithHierarchy } from "@/logic";

describe("GET /status-list endpoint", () => {
  const config = loadConfigWithHierarchy();
  const endpointUrl = `http://127.0.0.1:${config.trust_anchor.port}/status-list`;

  it("should respond with Content-Type application/statuslist+jwt", async () => {
    const response = await fetch(endpointUrl);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain(
      "application/statuslist+jwt",
    );
  });
});

describe("createStatusListToken", () => {
  const config = loadConfigWithHierarchy();
  const statusListEndpointBaseUrl = `http://127.0.0.1:${config.trust_anchor.port}`;
  const expectedSub = `${statusListEndpointBaseUrl}/status-list`;

  it("should set typ header to statuslist+jwt (spec §5.1)", async () => {
    const jwt = await createStatusListToken({
      statusListEndpointBaseUrl,
      trustAnchor: config.trust,
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.typ).toBe("statuslist+jwt");
  });

  it("should include required alg, kid and x5c in the header", async () => {
    const jwt = await createStatusListToken({
      statusListEndpointBaseUrl,
      trustAnchor: config.trust,
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBeDefined();
    expect(header.kid).toBeDefined();
    expect(Array.isArray(header.x5c)).toBe(true);
    expect((header.x5c as string[]).length).toBeGreaterThan(0);
  });

  it("should include required sub and iat payload claims (spec §5.1)", async () => {
    const jwt = await createStatusListToken({
      statusListEndpointBaseUrl,
      trustAnchor: config.trust,
    });

    const payload = decodeJwt(jwt);
    // sub MUST be the URI of the Status List Token (spec §5.1)
    expect(payload.sub).toBe(expectedSub);
    // iat REQUIRED (spec §5.1)
    expect(typeof payload.iat).toBe("number");
  });

  it("should include a valid status_list claim with bits=4 (spec §5.1, IT Wallet §4)", async () => {
    const jwt = await createStatusListToken({
      statusListEndpointBaseUrl,
      trustAnchor: config.trust,
    });

    const payload = decodeJwt(jwt);
    const statusListClaim = payload.status_list as
      | { bits: number; lst: string }
      | undefined;

    expect(statusListClaim).toBeDefined();
    // IT Wallet mandates ≥5 states → 4 bits per entry
    expect(statusListClaim?.bits).toBe(4);
    expect(typeof statusListClaim?.lst).toBe("string");
  });

  it("should produce a cryptographically valid signature using the x5c leaf cert (spec §8.3)", async () => {
    const jwt = await createStatusListToken({
      statusListEndpointBaseUrl,
      trustAnchor: config.trust,
    });

    const header = decodeProtectedHeader(jwt);
    const x5c = header.x5c as string[];
    const pem = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
    const publicKey = await importX509(pem, "ES256");

    await expect(
      jwtVerify(jwt, publicKey, { typ: "statuslist+jwt" }),
    ).resolves.toBeDefined();
  });

  it("should decompress the status list and report index 0 as VALID (0x00) (spec §8.3)", async () => {
    const jwt = await createStatusListToken({
      statusListEndpointBaseUrl,
      trustAnchor: config.trust,
    });

    const payload = decodeJwt(jwt);
    const { bits, lst } = payload.status_list as { bits: 1 | 2 | 4 | 8; lst: string };

    const list = StatusList.decompressStatusList(lst, bits);
    // Index 0 is always VALID (0x00) for mocked credentials
    expect(list.getStatus(0)).toBe(0x00);
  });

  it("should throw when the key pair is missing alg or x5c", async () => {
    vi.spyOn(utils, "loadJwksWithX5C").mockResolvedValueOnce({
      privateKey: { alg: "ES256", kty: "EC" } as never,
      publicKey: { kty: "EC" } as never, // no alg, no x5c
    });

    await expect(
      createStatusListToken({
        statusListEndpointBaseUrl,
        trustAnchor: config.trust,
      }),
    ).rejects.toThrow(
      "Unable to create status list token, public key is missing alg and x5c",
    );
  });
});
