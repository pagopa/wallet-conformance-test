import { createHash } from "node:crypto";

import type { PidIdentityConfig } from "@/types/pid-issuance";

import { encodeBerTlv, icaoLdsTag } from "@/logic/pid-mrtd/ber-tlv";

/** ICAO 9303 TD1 MRZ zone length (3 × 30 characters). */
export const TD1_MRZ_BYTE_LENGTH = 90;

const DG1_TAG = 0x61;
const DG11_TAG = 0x6b;

/** DG11 element tags (ICAO 9303 Part 10, JMRTD-aligned). */
const TAG_FULL_NAME = icaoLdsTag(0x0e);
const TAG_OTHER_NAME = icaoLdsTag(0x0f);
const TAG_PERSONAL_NUMBER = icaoLdsTag(0x10);
const TAG_PLACE_OF_BIRTH = icaoLdsTag(0x11);
const TAG_OTHER_TD_NUMBERS = icaoLdsTag(0x17);
const TAG_FULL_DATE_OF_BIRTH = icaoLdsTag(0x2b);

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
 * Builds DG11 (EF.DG11) as BER-TLV with valid ICAO two-byte tags (5F0E, 5F2B, …).
 * Holder name uses MRZ-style `SURNAME<<GIVEN`; birth date is `YYYYMMDD` (5F2B).
 */
export function buildDg11(identity: PidIdentityConfig): Uint8Array {
  const chunks: Uint8Array[] = [];

  const appendUtf8 = (tag: readonly number[], value: string): void => {
    chunks.push(encodeBerTlv(tag, new TextEncoder().encode(value)));
  };

  appendUtf8(
    TAG_FULL_NAME,
    `${identity.family_name}<<${identity.given_name}`.toUpperCase(),
  );
  appendUtf8(TAG_FULL_DATE_OF_BIRTH, isoDateToLdsBirthdate(identity.birthdate));
  appendUtf8(TAG_PLACE_OF_BIRTH, identity.place_of_birth);
  appendUtf8(TAG_PERSONAL_NUMBER, identity.tax_id_code);

  if (identity.personal_administrative_number) {
    appendUtf8(TAG_OTHER_TD_NUMBERS, identity.personal_administrative_number);
  }

  if (identity.nationalities?.length) {
    appendUtf8(TAG_OTHER_NAME, identity.nationalities.join(","));
  }

  const inner = concatUint8Arrays(chunks);
  return encodeBerTlv([DG11_TAG], inner);
}

/** SHA-256 digest used for SOD data group hash entries. */
export function sha256Digest(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/** Wraps raw DG bytes in a minimal DG1 container tag for hashing consistency. */
export function wrapDg1Container(mrzBytes: Uint8Array): Uint8Array {
  return encodeBerTlv([DG1_TAG], mrzBytes);
}

function concatUint8Arrays(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function isoDateToLdsBirthdate(isoDate: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(isoDate);
  if (!match) {
    throw new Error(`birthdate must be ISO-8601 YYYY-MM-DD, got '${isoDate}'`);
  }
  return `${match[1]}${match[2]}${match[3]}`;
}
