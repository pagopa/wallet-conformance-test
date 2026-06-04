import { createHash } from "node:crypto";

import type { PidIdentityConfig } from "@/types/pid-issuance";

/** ICAO 9303 TD1 MRZ zone length (3 × 30 characters). */
export const TD1_MRZ_BYTE_LENGTH = 90;

const DG1_TAG = 0x61;
const DG11_TAG = 0x6b;

/**
 * Builds DG1 bytes for TD1: MRZ padded/truncated to {@link TD1_MRZ_BYTE_LENGTH}.
 */
export function buildDg1(mrz: string): Uint8Array {
  const normalized = mrz.replace(/\s+/g, "").toUpperCase();
  const bytes = new Uint8Array(TD1_MRZ_BYTE_LENGTH).fill(0x3c);
  const encoded = new TextEncoder().encode(normalized);
  bytes.set(encoded.subarray(0, TD1_MRZ_BYTE_LENGTH));
  return bytes;
}

/**
 * Builds a simplified DG11 TLV structure from configured identity attributes.
 * Encoding is intentionally minimal (v1); strict ICAO TLV can be tightened with SUT feedback.
 */
export function buildDg11(identity: PidIdentityConfig): Uint8Array {
  const chunks: Buffer[] = [];

  const appendUtf8 = (tag: number, value: string): void => {
    const content = Buffer.from(value, "utf8");
    chunks.push(Buffer.from([tag, content.length]));
    chunks.push(content);
  };

  appendUtf8(0x5f, identity.given_name);
  appendUtf8(0x5f, identity.family_name);
  appendUtf8(0x5f, identity.birthdate);
  appendUtf8(0x5f, identity.place_of_birth);
  appendUtf8(0x5f, identity.tax_id_code);

  if (identity.personal_administrative_number) {
    appendUtf8(0x5f, identity.personal_administrative_number);
  }

  if (identity.nationalities?.length) {
    appendUtf8(0x5f, identity.nationalities.join(","));
  }

  const inner = Buffer.concat(chunks);
  const outer = Buffer.alloc(2 + inner.length);
  outer[0] = DG11_TAG;
  outer[1] = inner.length;
  inner.copy(outer, 2);

  return new Uint8Array(outer);
}

/** SHA-256 digest used for SOD data group hash entries. */
export function sha256Digest(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/** Wraps raw DG bytes in a minimal DG1 container tag for hashing consistency. */
export function wrapDg1Container(mrzBytes: Uint8Array): Uint8Array {
  const container = new Uint8Array(2 + mrzBytes.length);
  container[0] = DG1_TAG;
  container[1] = mrzBytes.length;
  container.set(mrzBytes, 2);
  return container;
}
