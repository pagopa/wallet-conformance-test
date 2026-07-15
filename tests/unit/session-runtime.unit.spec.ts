import { describe, expect, it } from "vitest";

import { resolveEntityNameFromEntityConfiguration } from "@/report/session-runtime";

describe("resolveEntityNameFromEntityConfiguration", () => {
  it("prefers the credential issuer display name for issuance", () => {
    expect(
      resolveEntityNameFromEntityConfiguration("issuance", {
        iss: "issuer.example",
        metadata: {
          federation_entity: {
            organization_name: "Federation fallback",
          },
          openid_credential_issuer: {
            display: [{ name: "Issuer display" }],
          },
        },
        sub: "subject.example",
      }),
    ).toBe("Issuer display");
  });

  it("falls back to the first non-empty presentation candidate", () => {
    expect(
      resolveEntityNameFromEntityConfiguration("presentation", {
        iss: "verifier.example",
        metadata: {
          federation_entity: {
            organization_name: "Verifier org",
          },
          openid_credential_verifier: {
            client_name: "   ",
          },
        },
        sub: "subject.example",
      }),
    ).toBe("Verifier org");
  });

  it("returns undefined for invalid claims", () => {
    expect(
      resolveEntityNameFromEntityConfiguration("issuance", null),
    ).toBeUndefined();
  });
});
