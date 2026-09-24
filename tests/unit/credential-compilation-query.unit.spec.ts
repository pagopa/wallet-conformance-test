import type { CredentialCompilationConfiguration } from "#/helpers/credential-compilation-query";

import { buildCredentialCompilationQuery } from "#/helpers/credential-compilation-query";
import { type DcqlMdocCredential, DcqlQuery } from "dcql";
import { describe, expect, it } from "vitest";

const namespace = "org.iso.18013.5.1";
const namespaceIdentifier = "org_iso_18013_5_1";

function buildMdocAlternativeConfiguration(): CredentialCompilationConfiguration {
  return {
    credential_metadata: {
      claims: [
        { mandatory: true, path: [namespace, "given_name"] },
        { mandatory: true, path: [namespace, "tax_id_code"] },
        {
          mandatory: true,
          path: [namespace, "personal_administrative_number"],
        },
      ],
    },
    format: "mso_mdoc",
  };
}

describe("CI_014 credential compilation query", () => {
  it("models namespaced mdoc identifiers as alternatives", () => {
    const query = buildCredentialCompilationQuery(
      buildMdocAlternativeConfiguration(),
      { credentialQueryId: "mdoc-alternative", isLegacy: false },
    );

    expect(query.credentials[0]?.claims).toEqual([
      {
        id: `${namespaceIdentifier}-given_name`,
        path: [namespace, "given_name"],
      },
      {
        id: `${namespaceIdentifier}-tax_id_code`,
        path: [namespace, "tax_id_code"],
      },
      {
        id: `${namespaceIdentifier}-personal_administrative_number`,
        path: [namespace, "personal_administrative_number"],
      },
    ]);
    expect(query.credentials[0]?.claim_sets).toEqual([
      [
        `${namespaceIdentifier}-given_name`,
        `${namespaceIdentifier}-tax_id_code`,
      ],
      [
        `${namespaceIdentifier}-given_name`,
        `${namespaceIdentifier}-personal_administrative_number`,
      ],
    ]);
  });

  it.each([
    ["tax_id_code", "TINIT-SYNTHETIC"],
    ["personal_administrative_number", "PAN-SYNTHETIC"],
  ] as const)(
    "allows an mdoc containing only %s to satisfy its alternative claim set",
    (identifier, value) => {
      const query = buildCredentialCompilationQuery(
        buildMdocAlternativeConfiguration(),
        { credentialQueryId: "mdoc-alternative", isLegacy: false },
      );
      const credential: DcqlMdocCredential = {
        credential_format: "mso_mdoc",
        cryptographic_holder_binding: true,
        doctype: "org.iso.18013.5.1.mDL",
        namespaces: {
          [namespace]: {
            given_name: "Ada",
            [identifier]: value,
          },
        },
      };

      const parsedQuery = DcqlQuery.parse(query);
      DcqlQuery.validate(parsedQuery);
      const result = DcqlQuery.query(parsedQuery, [credential]);

      expect(result.can_be_satisfied).toBe(true);
    },
  );

  it("does not classify nested SD-JWT identifier names as alternatives", () => {
    const query = buildCredentialCompilationQuery(
      {
        credential_metadata: {
          claims: [
            { mandatory: true, path: ["profile", "tax_id_code"] },
            {
              mandatory: true,
              path: ["profile", "personal_administrative_number"],
            },
          ],
        },
        format: "dc+sd-jwt",
      },
      { credentialQueryId: "nested-sd-jwt", isLegacy: false },
    );

    expect(query.credentials[0]?.claim_sets).toBeUndefined();
    expect(query.credentials[0]?.claims).toEqual([
      { path: ["profile", "tax_id_code"] },
      { path: ["profile", "personal_administrative_number"] },
    ]);
  });
});
