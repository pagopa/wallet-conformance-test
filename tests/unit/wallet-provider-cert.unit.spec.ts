import * as x509 from "@peculiar/x509";
import { beforeAll, describe, expect, it } from "vitest";

import { createKeys } from "@/logic/jwk";
import {
  createSignedCertificate,
  hasSanExtension,
  OID_SUBJECT_ALTERNATIVE_NAME,
} from "@/logic/pem";
import { LOCAL_WP_HOST } from "@/servers/wp-server";

describe("wallet_provider_cert SAN", () => {
  let certWithSan: x509.X509Certificate;
  let certWithSanDerBase64: string;
  let certWithoutSanDerBase64: string;

  beforeAll(async () => {
    const issuerKp = await createKeys();
    const subjectKp = await createKeys();
    certWithSan = await createSignedCertificate(
      issuerKp,
      "CN=TestIssuer",
      subjectKp,
      `CN=${LOCAL_WP_HOST}`,
      false,
      [
        new x509.SubjectAlternativeNameExtension(
          [{ type: "dns", value: LOCAL_WP_HOST }],
          false,
        ),
      ],
    );
    certWithSanDerBase64 = Buffer.from(certWithSan.rawData).toString("base64");

    const issuerKp2 = await createKeys();
    const subjectKp2 = await createKeys();
    const certWithoutSan = await createSignedCertificate(
      issuerKp2,
      "CN=TestIssuer",
      subjectKp2,
      `CN=${LOCAL_WP_HOST}`,
      false,
    );
    certWithoutSanDerBase64 = Buffer.from(certWithoutSan.rawData).toString(
      "base64",
    );
  });

  it("leaf cert created with SAN extension carries OID 2.5.29.17", () => {
    expect(
      certWithSan.getExtension(OID_SUBJECT_ALTERNATIVE_NAME),
      "SAN extension must be present",
    ).not.toBeNull();
  });

  it("hasSanExtension returns true for cert with SAN", () => {
    expect(
      hasSanExtension(certWithSanDerBase64),
      "hasSanExtension should return true when SAN is present",
    ).toBe(true);
  });

  it("hasSanExtension returns false for cert without SAN", () => {
    expect(
      hasSanExtension(certWithoutSanDerBase64),
      "hasSanExtension should return false when SAN is absent",
    ).toBe(false);
  });

  it("hasSanExtension returns false for an empty string", () => {
    expect(
      hasSanExtension(""),
      "empty string should not throw and should return false",
    ).toBe(false);
  });

  it("hasSanExtension returns false for malformed base64 input", () => {
    expect(
      hasSanExtension("not-valid-der-base64!!!"),
      "malformed input should not throw and should return false",
    ).toBe(false);
  });
});
