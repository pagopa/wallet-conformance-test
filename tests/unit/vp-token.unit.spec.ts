import type { CredentialCompilationConfiguration } from "#/helpers/credential-compilation-query";

import { buildCredentialCompilationQuery } from "#/helpers/credential-compilation-query";
import { digest } from "@sd-jwt/crypto-nodejs";
import { describe, expect, it } from "vitest";

import type { KeyPairJwk } from "@/types";

import { validateDcqlQuery } from "@/logic/dcql";
import { parseCredentialFromSdJwt } from "@/logic/vpToken";

interface SyntheticDisclosure {
  claim: string;
  salt: string;
  value: unknown;
}

function buildSyntheticSdJwt(): string {
  const disclosures: SyntheticDisclosure[] = [
    { claim: "given_name", salt: "salt-given", value: "Ada" },
    {
      claim: "place_of_birth",
      salt: "salt-place",
      value: { locality: "Roma" },
    },
    { claim: "nationalities", salt: "salt-nationality", value: ["IT"] },
    {
      claim: "tax_id_code",
      salt: "salt-tax-id",
      value: "TINIT-SYNTHETIC",
    },
  ];

  const encodedDisclosures = disclosures.map((disclosure) =>
    encodeJson([disclosure.salt, disclosure.claim, disclosure.value]),
  );
  const disclosureDigests = encodedDisclosures.map((disclosure) =>
    Buffer.from(digest(disclosure, "sha-256")).toString("base64url"),
  );

  const header = { alg: "ES256", typ: "dc+sd-jwt" };
  const payload = {
    _sd: disclosureDigests,
    _sd_alg: "sha-256",
    date_of_expiry: "2099-12-31",
    iss: "https://issuer.example.test",
    issuing_authority: "Synthetic Issuer",
    issuing_country: "IT",
    vct: "urn:eudi:test",
  };

  return `${encodeJson(header)}.${encodeJson(payload)}.synthetic-signature~${encodedDisclosures.join("~")}~`;
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

const syntheticCredential = buildSyntheticSdJwt();

describe("SD-JWT parsing and CI_014 DCQL query construction", () => {
  it("keeps direct JWT claims and stores disclosure values without SD metadata", async () => {
    const parsed = await parseCredentialFromSdJwt(syntheticCredential);

    expect(parsed.claims).toMatchObject({
      date_of_expiry: "2099-12-31",
      issuing_authority: "Synthetic Issuer",
      issuing_country: "IT",
      nationalities: ["IT"],
      place_of_birth: { locality: "Roma" },
      tax_id_code: "TINIT-SYNTHETIC",
    });
    expect(parsed.claims._sd).toBeUndefined();
    expect(parsed.claims._sd_alg).toBeUndefined();
    expect(Array.isArray(parsed.claims.nationalities)).toBe(true);
    expect(Array.isArray(parsed.claims.tax_id_code)).toBe(false);
  });

  it("uses only explicitly mandatory claims from latest metadata", () => {
    const configuration: CredentialCompilationConfiguration = {
      claims: [{ mandatory: true, path: ["legacy_claim"] }],
      credential_metadata: {
        claims: [
          { mandatory: true, path: ["given_name"] },
          { mandatory: "true", path: ["place_of_birth", "locality"] },
          { mandatory: false, path: ["place_of_birth", "region"] },
          { path: ["place_of_birth", "country"] },
          { path: ["nationalities"] },
        ],
      },
      format: "dc+sd-jwt",
      vct: "urn:eudi:test",
    };

    const query = buildCredentialCompilationQuery(configuration, {
      credentialQueryId: "synthetic",
      isLegacy: false,
    });
    const claims = query.credentials[0]?.claims ?? [];
    const claimPaths = claims.map((claim) => {
      if (!("path" in claim)) throw new Error("expected path-based claim");
      return claim.path;
    });

    expect(claimPaths).toEqual([
      ["given_name"],
      ["place_of_birth", "locality"],
    ]);
    expect(query.credentials[0]).toMatchObject({
      format: "dc+sd-jwt",
      id: "synthetic",
      meta: { vct_values: ["urn:eudi:test"] },
    });
  });

  it("uses credential_schema.claims for legacy versions", () => {
    const query = buildCredentialCompilationQuery(
      {
        claims: [
          { mandatory: true, path: ["birth_date"] },
          { mandatory: false, path: ["birth_place"] },
        ],
        credential_metadata: {
          claims: [{ mandatory: true, path: ["wrong_version_claim"] }],
        },
        format: "dc+sd-jwt",
      },
      { credentialQueryId: "legacy", isLegacy: true },
    );

    expect(query.credentials[0]?.claims).toEqual([{ path: ["birth_date"] }]);
  });

  it("models tax_id_code and personal_administrative_number as alternatives", () => {
    const query = buildCredentialCompilationQuery(
      {
        credential_metadata: {
          claims: [
            { mandatory: true, path: ["given_name"] },
            { mandatory: true, path: ["place_of_birth", "locality"] },
            { mandatory: true, path: ["tax_id_code"] },
            {
              mandatory: true,
              path: ["personal_administrative_number"],
            },
          ],
        },
        format: "dc+sd-jwt",
        vct: "urn:eudi:test",
      },
      { credentialQueryId: "alternative", isLegacy: false },
    );

    expect(query.credentials[0]?.claim_sets).toEqual([
      ["given_name", "place_of_birth-locality", "tax_id_code"],
      [
        "given_name",
        "place_of_birth-locality",
        "personal_administrative_number",
      ],
    ]);
  });

  it("validates a credential with tax_id_code and partial place_of_birth", async () => {
    const query = buildCredentialCompilationQuery(
      {
        credential_metadata: {
          claims: [
            { mandatory: true, path: ["given_name"] },
            { mandatory: true, path: ["place_of_birth", "locality"] },
            { mandatory: true, path: ["tax_id_code"] },
            {
              mandatory: true,
              path: ["personal_administrative_number"],
            },
          ],
        },
        format: "dc+sd-jwt",
        vct: "urn:eudi:test",
      },
      { credentialQueryId: "synthetic", isLegacy: false },
    );
    const publicKey: KeyPairJwk = {
      alg: "ES256",
      crv: "P-256",
      kid: "synthetic-key",
      kty: "EC",
      x: "synthetic-x",
      y: "synthetic-y",
    };

    await expect(
      validateDcqlQuery(
        [
          {
            credential: syntheticCredential,
            dpopJwk: publicKey,
            id: "synthetic",
            typ: "dc+sd-jwt",
          },
        ],
        query,
      ),
    ).resolves.toMatchObject({ can_be_satisfied: true });
  });
});
