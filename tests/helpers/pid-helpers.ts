import { expect } from "vitest";

export const assertPidJwtPayloadClaims = (
  payload: Record<string, unknown>,
  isV1_0: boolean,
): void => {
  expect(
    typeof payload["sub"] === "string" && (payload["sub"] as string).length > 0,
    "sub must be a non-empty string in the JWT payload",
  ).toBe(true);

  expect(typeof payload["iat"], "iat must be a number in the JWT payload").toBe(
    "number",
  );

  expect(
    typeof payload["cnf"] === "object" && payload["cnf"] !== null,
    "cnf must be a non-null object in the JWT payload",
  ).toBe(true);

  expect(
    typeof payload["status"] === "object" && payload["status"] !== null,
    "status must be a non-null object in the JWT payload",
  ).toBe(true);

  if (!isV1_0) {
    expect(
      typeof payload["verification"] === "object" &&
        payload["verification"] !== null,
      "verification must be a non-null object in the JWT payload (V1.3 domestic extension)",
    ).toBe(true);
  }
};

export const assertPidSdDisclosures = (
  disclosureMap: Map<string, unknown>,
  isV1_0: boolean,
): void => {
  expect(
    typeof disclosureMap.get("given_name"),
    "given_name must be a selectively disclosable string",
  ).toBe("string");

  expect(
    typeof disclosureMap.get("family_name"),
    "family_name must be a selectively disclosable string",
  ).toBe("string");

  const birthdateKey = isV1_0 ? "birth_date" : "birthdate";
  const birthdateValue = disclosureMap.get(birthdateKey);
  expect(
    birthdateValue,
    `${birthdateKey} must be present as a disclosure`,
  ).toBeDefined();
  expect(
    typeof birthdateValue === "string" &&
      /^\d{4}-\d{2}-\d{2}$/.test(birthdateValue),
    `${birthdateKey} must be a string in YYYY-MM-DD format`,
  ).toBe(true);

  if (isV1_0) {
    expect(
      typeof disclosureMap.get("birth_place"),
      "birth_place (V1.0) must be a selectively disclosable string",
    ).toBe("string");
  } else {
    const pob = disclosureMap.get("place_of_birth");
    expect(pob, "place_of_birth must be present as a disclosure").toBeDefined();
    expect(
      typeof pob === "object" && pob !== null && !Array.isArray(pob),
      "place_of_birth must be a JSON object",
    ).toBe(true);
    const pobObj = pob as Record<string, unknown>;
    expect(
      pobObj["country"] !== undefined ||
        pobObj["region"] !== undefined ||
        pobObj["locality"] !== undefined,
      "place_of_birth must contain at least one of: country, region, locality",
    ).toBe(true);
  }

  const nats = disclosureMap.get("nationalities");
  expect(nats, "nationalities must be present as a disclosure").toBeDefined();
  expect(Array.isArray(nats), "nationalities must be an array").toBe(true);
  for (const code of nats as unknown[]) {
    expect(
      typeof code === "string" && /^[A-Z]{2}$/.test(code),
      `nationalities entry "${String(code)}" must be an ISO 3166-1 alpha-2 code`,
    ).toBe(true);
  }

  const expiryKey = isV1_0 ? "expiry_date" : "date_of_expiry";
  expect(
    disclosureMap.get(expiryKey),
    `${expiryKey} must be present as a disclosure`,
  ).toBeDefined();

  const pan = disclosureMap.get("personal_administrative_number");
  const tic = disclosureMap.get("tax_id_code");
  expect(
    pan !== undefined || tic !== undefined,
    "At least one of personal_administrative_number or tax_id_code must be disclosed",
  ).toBe(true);
};
