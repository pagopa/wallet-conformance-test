/* eslint-disable no-bitwise -- ASN.1 DER length/tag encoding uses byte masks */
/** Minimal ASN.1 DER helpers for ICAO LDS Security Object encoding (REQ-03). */

export function derInteger(value: number): Uint8Array {
  const bytes =
    value <= 0xff
      ? new Uint8Array([value])
      : new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
  return derTag(0x02, false, bytes);
}

export function derOctetString(bytes: Uint8Array): Uint8Array {
  return derTag(0x04, false, bytes);
}

export function derOid(components: readonly number[]): Uint8Array {
  const first = components[0];
  const second = components[1];
  if (first === undefined || second === undefined) {
    throw new Error("OID must have at least two components");
  }

  const body: number[] = [first * 40 + second];
  for (let i = 2; i < components.length; i++) {
    const current = components[i];
    if (current === undefined) {
      continue;
    }
    let node = current;
    const encoded: number[] = [];
    encoded.unshift(node & 0x7f);
    node >>= 7;
    while (node > 0) {
      encoded.unshift((node & 0x7f) | 0x80);
      node >>= 7;
    }
    body.push(...encoded);
  }

  return derTag(0x06, false, new Uint8Array(body));
}

export function derSequence(children: readonly Uint8Array[]): Uint8Array {
  const total = children.reduce((sum, child) => sum + child.length, 0);
  const content = new Uint8Array(total);
  let offset = 0;
  for (const child of children) {
    content.set(child, offset);
    offset += child.length;
  }
  return derTag(0x30, true, content);
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  if (length < 0x100) {
    return new Uint8Array([0x81, length]);
  }
  if (length < 0x10000) {
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
  throw new RangeError(`DER length too large: ${length}`);
}

function derTag(
  tag: number,
  constructed: boolean,
  content: Uint8Array,
): Uint8Array {
  const tagByte = (constructed ? 0x20 : 0) | tag;
  const len = derLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tagByte;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}
