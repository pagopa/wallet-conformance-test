import { describe, expect, it } from "vitest";

import { normalizeClientId } from "@/logic/utils";

describe("normalizeClientId", () => {
  it("removes openid_federation: prefix", () => {
    expect(normalizeClientId("openid_federation:https://rp.example.com")).toBe(
      "https://rp.example.com",
    );
  });

  it("removes an arbitrary single-segment prefix", () => {
    expect(normalizeClientId("custom_scheme:https://rp.example.com")).toBe(
      "https://rp.example.com",
    );
  });

  it("leaves a plain HTTPS URL unchanged", () => {
    expect(normalizeClientId("https://rp.example.com")).toBe(
      "https://rp.example.com",
    );
  });

  it("leaves a plain HTTP URL unchanged", () => {
    expect(normalizeClientId("http://rp.example.com")).toBe(
      "http://rp.example.com",
    );
  });

  it("does not strip a URL that contains a path with a colon", () => {
    // Should not be affected — the regex only matches up to the first ':'
    // followed immediately by https?://
    expect(normalizeClientId("https://rp.example.com/path:extra")).toBe(
      "https://rp.example.com/path:extra",
    );
  });
});
