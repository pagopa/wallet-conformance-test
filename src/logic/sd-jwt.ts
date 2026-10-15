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
