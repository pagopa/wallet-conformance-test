import { StatusList } from "@sd-jwt/jwt-status-list";
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from "jose";
import { describe, expect, it, vi } from "vitest";

import { loadConfigWithHierarchy } from "@/logic";
import * as pem from "@/logic/pem";
import { createStatusListToken } from "@/logic/status-list";
import * as utils from "@/logic/utils";
import { getLocalCiBaseUrl } from "@/servers/ci-server";
import { getLocalWpBaseUrl } from "@/servers/wp-server";

describe("status-list endpoint tests", () => {
  const config = loadConfigWithHierarchy();

  describe.each([
    {
      baseUrl: `https://127.0.0.1:${config.wallet.port}`,
      expectedIss: getLocalWpBaseUrl(config.wallet.port),
      expectedSub: `${getLocalWpBaseUrl(config.wallet.port)}/status-list`,
      path: "/status-list",
    },
    {
      baseUrl: `https://127.0.0.1:${config.issuer.port}`,
      expectedIss: getLocalCiBaseUrl(config.issuer.port),
      expectedSub: `${getLocalCiBaseUrl(config.issuer.port)}/status-list`,
      path: "/status-list",
    },
  ])(
    "GET $path ($expectedIss)",
    ({ baseUrl, expectedIss, expectedSub, path }) => {
      const endpointUrl = `${baseUrl}${path}`;

      it("should respond with Content-Type application/statuslist+jwt", async () => {
        const response = await fetch(endpointUrl);

        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toContain(
          "application/statuslist+jwt",
        );
      });

      it("should set the correct iss and sub to the endpoint URI", async () => {
        const response = await fetch(endpointUrl);
        const jwt = await response.text();
        const payload = decodeJwt(jwt);

        expect(payload.iss).toBe(expectedIss);
        expect(payload.sub).toBe(expectedSub);
      });

      it("should include x5c in the header and produce a valid signature", async () => {
        const response = await fetch(endpointUrl);
        const jwt = await response.text();
        const header = decodeProtectedHeader(jwt);

        expect(Array.isArray(header.x5c)).toBe(true);
        const pem = `-----BEGIN CERTIFICATE-----\n${(header.x5c as string[])[0]}\n-----END CERTIFICATE-----`;
        const publicKey = await importX509(pem, "ES256");

        await expect(
          jwtVerify(jwt, publicKey, { typ: "statuslist+jwt" }),
        ).resolves.toBeDefined();
      });
    },
  );
});

describe("createStatusListToken", () => {
  const config = loadConfigWithHierarchy();
  const statusListEndpointBaseUrl = `http://127.0.0.1:${config.wallet.port}`;

  const walletOptions = {
    certFilename: "wallet_provider_cert",
    certSubject: `CN=wallet-provider.wct.example.org`,
    iss: getLocalWpBaseUrl(config.wallet.port),
    jwksFilename: "wallet_provider_jwks",
    jwksPath: config.wallet.backup_storage_path,
    statusListEndpointUrl: `${statusListEndpointBaseUrl}/status-list`,
  };

  it("should set typ header to statuslist+jwt (spec §5.1)", async () => {
    const jwt = await createStatusListToken(walletOptions);

    const header = decodeProtectedHeader(jwt);
    expect(header.typ).toBe("statuslist+jwt");
  });

  it("should include required alg, kid and x5c in the header", async () => {
    const jwt = await createStatusListToken(walletOptions);

    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBeDefined();
    expect(header.kid).toBeDefined();
    expect(Array.isArray(header.x5c)).toBe(true);
    expect((header.x5c as string[]).length).toBeGreaterThan(0);
  });

  it("should include required iss, sub and iat payload claims (spec §5.1)", async () => {
    const jwt = await createStatusListToken(walletOptions);

    const payload = decodeJwt(jwt);
    expect(payload.iss).toBe(walletOptions.iss);
    // sub MUST be the URI of the Status List Token (spec §5.1)
    expect(payload.sub).toBe(walletOptions.statusListEndpointUrl);
    // iat REQUIRED (spec §5.1)
    expect(typeof payload.iat).toBe("number");
  });

  it("should include a valid status_list claim with bits=4 (spec §5.1, IT Wallet §4)", async () => {
    const jwt = await createStatusListToken(walletOptions);

    const payload = decodeJwt(jwt);
    const statusListClaim = payload.status_list as
      | undefined
      | { bits: number; lst: string };

    expect(statusListClaim).toBeDefined();
    // IT Wallet mandates ≥5 states → 4 bits per entry
    expect(statusListClaim?.bits).toBe(4);
    expect(typeof statusListClaim?.lst).toBe("string");
  });

  it("should produce a cryptographically valid signature using the x5c leaf cert (spec §8.3)", async () => {
    const jwt = await createStatusListToken(walletOptions);

    const header = decodeProtectedHeader(jwt);
    const x5c = header.x5c as string[];
    const pem = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
    const publicKey = await importX509(pem, "ES256");

    await expect(
      jwtVerify(jwt, publicKey, { typ: "statuslist+jwt" }),
    ).resolves.toBeDefined();
  });

  it("should decompress the status list and report index 0 as VALID (0x00) (spec §8.3)", async () => {
    const jwt = await createStatusListToken(walletOptions);

    const payload = decodeJwt(jwt);
    const { bits, lst } = payload.status_list as {
      bits: 1 | 2 | 4 | 8;
      lst: string;
    };

    const list = StatusList.decompressStatusList(lst, bits);
    // Index 0 is always VALID (0x00) for mocked credentials
    expect(list.getStatus(0)).toBe(0x00);
  });

  it("should throw when the key pair is missing alg", async () => {
    vi.spyOn(utils, "loadJwks").mockResolvedValueOnce({
      privateKey: { alg: "ES256", kty: "EC" } as never,
      publicKey: { kty: "EC" } as never, // no alg
    });
    vi.spyOn(pem, "loadCertificate").mockResolvedValueOnce("dummycert");

    await expect(createStatusListToken(walletOptions)).rejects.toThrow(
      /Error, the following keys are missing from object: alg/,
    );
  });
});
