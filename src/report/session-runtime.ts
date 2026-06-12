import type { Phase } from "@/report/types";

import { openDb, resolveDbPath } from "@/report/db";
import {
  getLatestOpenSessionId,
  updateSessionEntityName,
} from "@/report/session-store";

export function recordSessionEntityNameFromEntityConfiguration(
  phase: Phase,
  entityStatementClaims: unknown,
): void {
  const db = openDb(resolveDbPath());

  try {
    const sessionId = getLatestOpenSessionId(db, phase);
    if (!sessionId) {
      return;
    }

    const entityName = resolveEntityNameFromEntityConfiguration(
      phase,
      entityStatementClaims,
    );

    if (!entityName) {
      return;
    }

    updateSessionEntityName(db, sessionId, entityName);
  } finally {
    db.close();
  }
}

export function resolveEntityNameFromEntityConfiguration(
  phase: Phase,
  entityStatementClaims: unknown,
): string | undefined {
  const claims = getRecord(entityStatementClaims);
  if (!claims) {
    return undefined;
  }

  const metadata = getRecord(claims.metadata);
  const federationEntity = getRecord(metadata?.federation_entity);

  if (phase === "issuance") {
    const credentialIssuer = getRecord(metadata?.openid_credential_issuer);

    return (
      getDisplayName(credentialIssuer?.display) ??
      getString(federationEntity?.organization_name) ??
      getString(claims.iss) ??
      getString(claims.sub)
    );
  }

  const credentialVerifier = getRecord(metadata?.openid_credential_verifier);

  return (
    getString(credentialVerifier?.client_name) ??
    getString(federationEntity?.organization_name) ??
    getString(claims.iss) ??
    getString(claims.sub)
  );
}

function getDisplayName(display: unknown): string | undefined {
  if (!Array.isArray(display)) {
    return undefined;
  }

  for (const entry of display) {
    const name = getString(getRecord(entry)?.name);
    if (name !== undefined) {
      return name;
    }
  }

  return undefined;
}

function getRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }

  return value as Record<string, unknown>;
}

function getString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}
