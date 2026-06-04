import {
  derInteger,
  derOctetString,
  derOid,
  derSequence,
} from "@/logic/pid-mrtd/der";

/** id-icao-mrtdSecurityObject (LDS Security Object). */
export const OID_ICAO_LDS_SECURITY_OBJECT = [
  0, 4, 0, 127, 0, 7, 2, 2, 1,
] as const;

/** id-sha256 (NIST). */
export const OID_SHA256 = [2, 16, 840, 1, 101, 3, 4, 2, 1] as const;

export interface DataGroupHashEntry {
  dataGroupNumber: number;
  hash: Uint8Array;
}

/**
 * Encodes an ICAO LDS Security Object (version 1, SHA-256) as DER.
 * Used as the eContent payload inside CMS SignedData (SOD_MRTD / SOD_IAS).
 */
export function encodeLdsSecurityObject(
  entries: readonly DataGroupHashEntry[],
): Uint8Array {
  if (entries.length === 0) {
    throw new Error(
      "LDS Security Object requires at least one data group hash",
    );
  }

  for (const entry of entries) {
    if (entry.hash.length !== 32) {
      throw new Error(
        `DG${entry.dataGroupNumber} hash must be 32 bytes (SHA-256), got ${entry.hash.length}`,
      );
    }
  }

  const dgHashes = entries.map((entry) =>
    derSequence([
      derInteger(entry.dataGroupNumber),
      derOctetString(entry.hash),
    ]),
  );

  return derSequence([
    derInteger(1),
    derOid(OID_SHA256),
    derSequence(dgHashes),
  ]);
}
