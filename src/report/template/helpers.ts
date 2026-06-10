import type { ComplianceTier } from "@/report/template/types";
import type { Config } from "@/types";

import { Phase } from "../types";

// ─── String escaping ──────────────────────────────────────────────────────────

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// ─── Date formatting ──────────────────────────────────────────────────────────

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }

  return date.toLocaleString("it-IT", {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

export function formatGeneratedAt(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }

  return date.toLocaleString("it-IT", {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "2-digit",
    second: "2-digit",
    year: "numeric",
  });
}

// ─── Compliance resolvers ─────────────────────────────────────────────────────

export function resolveComplianceTier(pct: number): ComplianceTier {
  if (pct === 100) return "passed";
  if (pct < 50) return "failed";
  return "partial";
}

export function resolveEntityName(config?: Config): string {
  const subject = config?.trust.certificate_subject;
  if (!subject) {
    return "-";
  }

  const orgMatch = /\bO=([^,]+)/.exec(subject);
  if (orgMatch?.[1]) {
    return orgMatch[1].trim();
  }

  const cnMatch = /\bCN=([^,]+)/.exec(subject);
  if (cnMatch?.[1]) {
    return cnMatch[1].trim();
  }

  return subject;
}

/**
 * Resolves the conformance profile label from the session phase.
 * The phase is set authoritatively by the reporter at session creation
 * time based on which Vitest config was used (issuance vs presentation).
 */
export function resolveProfile(phase: Phase): string {
  if (phase === "issuance") {
    return "Credential Issuer (CI)";
  }

  if (phase === "presentation") {
    return "Relying Party (RP)";
  }

  throw new Error(`Unknown phase: ${phase}`);
}

export function resolveTierLabel(tier: ComplianceTier): string {
  if (tier === "passed") return "Conformità Completa";
  if (tier === "failed") return "Bassa Conformità";
  return "Conformità Parziale";
}
