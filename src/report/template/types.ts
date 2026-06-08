import type { ConformanceCheck } from "@/report/types";

// ─── Types ────────────────────────────────────────────────────────────────────

export type ComplianceTier = "failed" | "partial" | "passed";

/**
 * Pre-computed, view-agnostic data derived from a ConformanceSession + Config.
 * Both the executive and technical views consume this shape.
 */
export interface ReportData {
  checkCards: string;
  checks: ConformanceCheck[];
  compliancePct: number;
  complianceTier: ComplianceTier;
  criticalChecks: ConformanceCheck[];
  entityName: string;
  executedAt: string;
  failCount: number;
  generatedAt: string;
  partialCount: number;
  passCount: number;
  profile: string;
  reportId: string;
  sessionId: string;
  solutionName: string;
  specVersion: string;
  statusLabel: string;
  totalChecks: number;
  versionPill: string;
}
