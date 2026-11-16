import { describe, expect, it } from "vitest";

import { collectDisclosureDigests } from "@/logic/sd-jwt";

describe("collectDisclosureDigests", () => {
  it("returns the digests of the top-level _sd array", () => {
    const payload = { _sd: ["a", "b"], _sd_alg: "sha-256", iss: "x" };

    expect(collectDisclosureDigests(payload)).toEqual(["a", "b"]);
  });

  it("returns the digests of a nested object's _sd array", () => {
    const payload = { _sd: ["a"], address: { _sd: ["b", "c"] } };

    expect(collectDisclosureDigests(payload)).toEqual(["a", "b", "c"]);
  });

  it("returns array-element digests written as {'...': digest}", () => {
    const payload = { nationalities: [{ "...": "a" }, "IT", { "...": "b" }] };

    expect(collectDisclosureDigests(payload)).toEqual(["a", "b"]);
  });

  it("collects digests from a disclosure value into the same list", () => {
    const found = collectDisclosureDigests({ _sd: ["a"] });
    // the value of a disclosed array claim whose elements are disclosures too
    collectDisclosureDigests([{ "...": "b" }, { "...": "c" }], found);

    expect(found).toEqual(["a", "b", "c"]);
  });

  it("ignores values that are not digests", () => {
    const payload = { _sd: ["a", 1, null], list: [{ "...": 2 }, { x: 1 }] };

    expect(collectDisclosureDigests(payload)).toEqual(["a"]);
  });
});
