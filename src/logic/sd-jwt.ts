import { SDJwt } from "@sd-jwt/core";
import { digest } from "@sd-jwt/crypto-nodejs";
import { importJWK, SignJWT } from "jose";
import crypto from "node:crypto";

import { DcqlClaimPath, VpTokenOptions } from "@/types";

interface PresentationFrameObject {
  [key: string]: PresentationFrameValue;
}

type PresentationFrameValue = boolean | PresentationFrameObject;

/**
 * Returns every disclosure digest that appears in an SD-JWT payload, or in a
 * disclosure value, wherever SD-JWT places it: in any object's `_sd` array,
 * and in arrays as `{"...": digest}` for array-element disclosures.
 *
 * @param value - The SD-JWT payload, or the value of a disclosure
 * @param found - Accumulator, so several values can be collected into one list
 * @returns The digests found
 */
export function collectDisclosureDigests(
  value: unknown,
  found: string[] = [],
): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      if (
        item &&
        typeof item === "object" &&
        !Array.isArray(item) &&
        "..." in item
      ) {
        const digest = (item as Record<string, unknown>)["..."];
        if (typeof digest === "string") found.push(digest);
      } else {
        collectDisclosureDigests(item, found);
      }
    }
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "_sd" && Array.isArray(child)) {
        found.push(...child.filter((d): d is string => typeof d === "string"));
      } else {
        collectDisclosureDigests(child, found);
      }
    }
  }
  return found;
}

/**
 * Creates a VP Token SD-JWT by combining the provided SD-JWT with a Key Binding JWT (KB-JWT).
 * @param param0
 * @returns
 */
export async function createVpTokenSdJwt(
  options: Omit<VpTokenOptions, "dcqlQuery" | "responseUri">,
): Promise<string> {
  const sdJwt = await SDJwt.fromEncode(options.credential, digest);
  const selectedDisclosures = await sdJwt.getPresentDisclosures(
    createPresentationFrame(options.dcqlClaimPaths ?? []),
    digest,
  );
  const selectedDisclosureEncodings = new Set(
    selectedDisclosures.map((disclosure) => disclosure.encode()),
  );
  const selectiveSdJwt = new SDJwt({
    disclosures: (sdJwt.disclosures ?? []).filter((disclosure) =>
      selectedDisclosureEncodings.has(disclosure.encode()),
    ),
    jwt: sdJwt.jwt,
  }).encodeSDJwt();

  const sd_hash = crypto
    .createHash("sha256")
    .update(selectiveSdJwt)
    .digest("base64url");

  // Use dpop key for the key binding JWT (wallet holder's key)
  const dpopPrivateKey = await importJWK(options.dpopJwk, "ES256");
  const kbJwt = await new SignJWT({
    nonce: options.nonce,
    sd_hash,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "kb+jwt",
    })
    .setAudience(options.client_id)
    .setIssuedAt()
    .sign(dpopPrivateKey);

  // <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>

  return `${selectiveSdJwt}${kbJwt}`;
}

export function generateSRIHash(content: string): string {
  const digest = crypto.createHash("sha256").update(content).digest("base64");
  return `sha256-${digest}`;
}

function addClaimPath(
  frame: PresentationFrameObject,
  claimPath: DcqlClaimPath,
  pathIndex: number,
): void {
  const segment = claimPath[pathIndex];
  if (segment === undefined) return;

  const key = String(segment);
  if (pathIndex === claimPath.length - 1) {
    frame[key] = true;
    return;
  }

  if (frame[key] === true) return;

  const childFrame = isPresentationFrameObject(frame[key]) ? frame[key] : {};
  frame[key] = childFrame;
  addClaimPath(childFrame, claimPath, pathIndex + 1);
}

function createPresentationFrame(
  claimPaths: DcqlClaimPath[],
): PresentationFrameObject {
  const frame: PresentationFrameObject = {};

  for (const claimPath of claimPaths) {
    addClaimPath(frame, claimPath, 0);
  }

  return frame;
}

function isPresentationFrameObject(
  value: PresentationFrameValue | undefined,
): value is PresentationFrameObject {
  return typeof value === "object" && value !== null;
}
