import { extractClientIdPrefix } from "@pagopa/io-wallet-oid4vp";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeSdJwt } from "@sd-jwt/decode";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator";

import { postToResponseUri } from "./http-helpers";

export interface RequestedPresentation {
  format: string;
  id: string;
}

export interface SdJwtKbJwtPresentation {
  id: string;
  kbJwt: string;
  presentation: string;
}

export function assertSignedPresentation(
  requestedPresentation: RequestedPresentation,
  presentation: unknown,
): void {
  const { format, id } = requestedPresentation;
  if (format === "dc+sd-jwt") {
    readSdJwtPresentationParts(id, presentation);
    return;
  }

  if (typeof presentation !== "string" || presentation.length === 0) {
    throw new Error(`vp_token.${id} contains an empty presentation`);
  }

  if (format === "mso_mdoc") {
    if (!/^[A-Za-z0-9_-]+$/.test(presentation)) {
      throw new Error(`vp_token.${id} is not a base64url mdoc VP`);
    }
    return;
  }

  throw new Error(`Unsupported requested presentation format: ${format}`);
}

export function assertVpTokenRecord(
  vpToken: unknown,
): asserts vpToken is Record<string, string | string[] | undefined> {
  if (!vpToken || typeof vpToken !== "object" || Array.isArray(vpToken)) {
    throw new Error("vp_token must be an object keyed by DCQL credential id");
  }
}

export function isCompactJwt(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

export function normalizePresentationArray(
  id: string,
  presentationOrArray: string | string[] | undefined,
  walletVersion: ItWalletSpecsVersion,
): string[] {
  if (!presentationOrArray) {
    throw new Error(`vp_token.${id} is missing`);
  }
  if (
    walletVersion === ItWalletSpecsVersion.V1_3 &&
    !Array.isArray(presentationOrArray)
  ) {
    throw new Error(`vp_token.${id} must be a presentation array`);
  }

  const presentations = Array.isArray(presentationOrArray)
    ? presentationOrArray
    : [presentationOrArray];
  if (presentations.length === 0) {
    throw new Error(`vp_token.${id} must contain at least one presentation`);
  }

  return presentations;
}

export function normalizeUriBasePath(uri: string): string {
  const url = new URL(uri);
  const pathname = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${pathname}`;
}

export async function postFreshValidAuthorizationResponse(
  orchestrator: WalletPresentationOrchestratorFlow,
): Promise<Response> {
  const ctx = await orchestrator.runThroughAuthorize();
  const authResponse = ctx.authorizationRequestResponse.response;
  if (!authResponse) {
    throw new Error(
      "Setup failed: authorizationRequestResponse.response is undefined — RP did not return a valid authorization response",
    );
  }

  const formBody = new URLSearchParams({
    response: authResponse.authorizationResponse.jarm.responseJwe,
  });

  return postToResponseUri(authResponse.responseUri, {
    body: formBody.toString(),
  });
}

export function readDcqlClaimPaths(
  credential: unknown,
  credentialIndex: number,
): string[][] {
  if (!credential || typeof credential !== "object") {
    throw new Error(
      `dcql_query.credentials[${credentialIndex}] must be an object`,
    );
  }

  const claims = (credential as { claims?: unknown }).claims;
  if (claims === undefined) {
    return [];
  }
  if (!Array.isArray(claims)) {
    throw new Error(
      `dcql_query.credentials[${credentialIndex}].claims must be an array`,
    );
  }

  return claims.map((claim, claimIndex) => {
    if (!claim || typeof claim !== "object") {
      throw new Error(
        `dcql_query.credentials[${credentialIndex}].claims[${claimIndex}] must be an object`,
      );
    }

    const path = (claim as { path?: unknown }).path;
    if (!Array.isArray(path) || path.length === 0) {
      throw new Error(
        `dcql_query.credentials[${credentialIndex}].claims[${claimIndex}].path must be a non-empty array`,
      );
    }

    return path.map((segment) => {
      if (typeof segment !== "string" && typeof segment !== "number") {
        throw new Error(
          `dcql_query.credentials[${credentialIndex}].claims[${claimIndex}].path contains an unsupported segment`,
        );
      }
      return String(segment);
    });
  });
}

export function readDcqlCredentials(requestObject: unknown): unknown[] {
  if (!requestObject || typeof requestObject !== "object") {
    throw new Error("requestObject is missing");
  }

  const dcqlQuery = (requestObject as { dcql_query?: unknown }).dcql_query;
  if (!dcqlQuery || typeof dcqlQuery !== "object") {
    throw new Error("requestObject.dcql_query is missing");
  }

  const credentials = (dcqlQuery as { credentials?: unknown }).credentials;
  if (!Array.isArray(credentials) || credentials.length === 0) {
    throw new Error("dcql_query.credentials must contain at least one entry");
  }

  return credentials;
}

export function readRelyingPartyIdentifier(
  requestObject: unknown,
  parsedQrCode: unknown,
): string {
  if (requestObject && typeof requestObject === "object") {
    const clientId = (requestObject as { client_id?: unknown }).client_id;
    if (typeof clientId === "string" && clientId.length > 0) {
      return extractClientIdPrefix(clientId).clientId;
    }
  }

  return readRequiredStringProperty(parsedQrCode, "clientId", "parsedQrCode");
}

export function readRequestedPresentation(
  credential: unknown,
  index: number,
): RequestedPresentation {
  if (!credential || typeof credential !== "object") {
    throw new Error(`dcql_query.credentials[${index}] must be an object`);
  }

  const { format, id } = credential as { format?: unknown; id?: unknown };
  if (typeof id !== "string" || id.length === 0) {
    throw new Error(`dcql_query.credentials[${index}].id must be a string`);
  }
  if (typeof format !== "string" || format.length === 0) {
    throw new Error(`dcql_query.credentials[${index}].format must be a string`);
  }

  return { format, id };
}

export function readRequiredStringProperty(
  value: unknown,
  property: string,
  label: string,
): string {
  if (!value || typeof value !== "object") {
    throw new Error(`${label} is missing`);
  }

  const propertyValue = (value as Record<string, unknown>)[property];
  if (typeof propertyValue !== "string" || propertyValue.length === 0) {
    throw new Error(`${label}.${property} must be a non-empty string`);
  }

  return propertyValue;
}

export async function readSdJwtDisclosedClaimNames(
  presentation: string,
): Promise<Set<string>> {
  const decodedPresentation = await decodeSdJwt(presentation, digest);

  return new Set(
    decodedPresentation.disclosures.flatMap((disclosure) => {
      const disclosureData = disclosure.decode();
      const claimName = disclosureData[1];
      return typeof claimName === "string" ? [claimName] : [];
    }),
  );
}

export function readSdJwtKbJwtPresentations(
  vpToken: Record<string, string | string[] | undefined>,
  requestedPresentations: RequestedPresentation[],
  walletVersion: ItWalletSpecsVersion,
): SdJwtKbJwtPresentation[] {
  const sdJwtRequests = requestedPresentations.filter(
    ({ format }) => format === "dc+sd-jwt",
  );
  if (sdJwtRequests.length === 0) {
    throw new Error("KB-JWT tests require at least one dc+sd-jwt presentation");
  }

  return sdJwtRequests.flatMap(({ id }) => {
    const presentations = normalizePresentationArray(
      id,
      vpToken[id],
      walletVersion,
    );

    return presentations.map((presentation) => {
      const { kbJwt } = readSdJwtPresentationParts(id, presentation);
      return { id, kbJwt, presentation };
    });
  });
}

export function readSdJwtKbJwtPresentationsForRequest(
  requestObject: unknown,
  vpToken: unknown,
  walletVersion: ItWalletSpecsVersion,
): SdJwtKbJwtPresentation[] {
  const requestedPresentations = readDcqlCredentials(requestObject).map(
    (credential, index) => readRequestedPresentation(credential, index),
  );
  assertVpTokenRecord(vpToken);

  return readSdJwtKbJwtPresentations(
    vpToken,
    requestedPresentations,
    walletVersion,
  );
}

export function readSdJwtPresentationParts(
  id: string,
  presentation: unknown,
): { issuerJwt: string; kbJwt: string; presentation: string } {
  if (typeof presentation !== "string" || presentation.length === 0) {
    throw new Error(`vp_token.${id} contains an empty presentation`);
  }

  const sdJwtParts = presentation.split("~");
  const issuerJwt = sdJwtParts[0];
  const kbJwt = sdJwtParts[sdJwtParts.length - 1];
  if (sdJwtParts.length < 2 || !issuerJwt || !kbJwt) {
    throw new Error(`vp_token.${id} is not a signed SD-JWT VP`);
  }
  if (!isCompactJwt(issuerJwt) || !isCompactJwt(kbJwt)) {
    throw new Error(`vp_token.${id} is missing signed JWT segments`);
  }

  return { issuerJwt, kbJwt, presentation };
}

export function uriMatchesDeclaredBasePath(
  uri: string,
  declaredBasePath: string,
): boolean {
  const actualBasePath = normalizeUriBasePath(uri);
  const normalizedDeclaredBasePath = normalizeUriBasePath(declaredBasePath);
  return (
    actualBasePath === normalizedDeclaredBasePath ||
    actualBasePath.startsWith(`${normalizedDeclaredBasePath}/`)
  );
}
