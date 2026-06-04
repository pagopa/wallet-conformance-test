import * as x509 from "@peculiar/x509";
import { describe, expect, it } from "vitest";

import { createKeys } from "@/logic/jwk";
import { createSignedCertificate, hasSanExtension } from "@/logic/pem";
import { LOCAL_WP_HOST } from "@/servers/wp-server";

const SAN_OID = "2.5.29.17";

describe("wallet_provider_cert SAN", () => {
  it("leaf cert created with SAN contains the expected dNSName entry", async () => {
    const issuerKeyPair = await createKeys();
    const subjectKeyPair = await createKeys();

    const cert = await createSignedCertificate(
      issuerKeyPair,
      "CN=TestIssuer",
      subjectKeyPair,
      `CN=${LOCAL_WP_HOST}`,
      false,
      [
        new x509.SubjectAlternativeNameExtension(
          [{ type: "dns", value: LOCAL_WP_HOST }],
          false,
        ),
      ],
    );

    expect(
      cert.getExtension(SAN_OID),
      "SAN extension (OID 2.5.29.17) must be present",
    ).not.toBeNull();
  });

  it("hasSanExtension returns true for a cert that carries a SAN", async () => {
    const issuerKeyPair = await createKeys();
    const subjectKeyPair = await createKeys();

    const cert = await createSignedCertificate(
      issuerKeyPair,
      "CN=TestIssuer",
      subjectKeyPair,
      `CN=${LOCAL_WP_HOST}`,
      false,
      [
        new x509.SubjectAlternativeNameExtension(
          [{ type: "dns", value: LOCAL_WP_HOST }],
          false,
        ),
      ],
    );

    const certDerBase64 = Buffer.from(cert.rawData).toString("base64");
    expect(
      hasSanExtension(certDerBase64),
      "hasSanExtension should return true when SAN is present",
    ).toBe(true);
  });

  it("hasSanExtension returns false for a cert without SAN", async () => {
    const issuerKeyPair = await createKeys();
    const subjectKeyPair = await createKeys();

    const cert = await createSignedCertificate(
      issuerKeyPair,
      "CN=TestIssuer",
      subjectKeyPair,
      `CN=${LOCAL_WP_HOST}`,
      false,
    );

    const certDerBase64 = Buffer.from(cert.rawData).toString("base64");
    expect(
      hasSanExtension(certDerBase64),
      "hasSanExtension should return false when SAN is absent",
    ).toBe(false);
  });
});
