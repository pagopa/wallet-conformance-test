/* eslint-disable no-bitwise -- BER-TLV length/tag encoding uses byte masks */

/**
 * BER-TLV encoder for ICAO LDS data groups (ISO/IEC 7816-4 style).
 * Two-byte tags use 0x5F as the first octet (tag number continuation follows).
 */

/** Builds a primitive BER-TLV object (shortest length encoding). */
export function encodeBerTlv(
  tag: readonly number[],
  value: Uint8Array,
): Uint8Array {
  if (tag.length === 0) {
    throw new Error("TLV tag must contain at least one byte");
  }

  const length = encodeBerTlvLength(value.length);
  const out = new Uint8Array(tag.length + length.length + value.length);
  out.set(tag, 0);
  out.set(length, tag.length);
  out.set(value, tag.length + length.length);
  return out;
}

export function encodeBerTlvLength(length: number): Uint8Array {
  if (length < 0) {
    throw new RangeError(`Invalid TLV length: ${length}`);
  }
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  if (length < 0x100) {
    return new Uint8Array([0x81, length]);
  }
  if (length < 0x10000) {
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
  throw new RangeError(`TLV length too large: ${length}`);
}

/** ICAO LDS two-byte tag: 0x5F || elementId (e.g. 0x0E → 5F0E). */
export function icaoLdsTag(elementId: number): readonly [0x5f, number] {
  if (elementId < 0 || elementId > 0xff) {
    throw new RangeError(`Invalid ICAO LDS element id: ${elementId}`);
  }
  return [0x5f, elementId];
}
