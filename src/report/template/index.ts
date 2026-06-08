import type { ReportData } from "@/report/template/types";
import type { ConformanceSession } from "@/report/types";
import type { Config } from "@/types";

import { readPackageVersion } from "@/logic/config-loader";
import { renderExecutiveView } from "@/report/template/executive-view";
import {
  formatDateTime,
  formatGeneratedAt,
  resolveComplianceTier,
  resolveEntityName,
  resolveProfile,
  resolveTierLabel,
} from "@/report/template/helpers";
import { renderCheckCard } from "@/report/template/shared";
import { REPORT_CSS } from "@/report/template/styles";
import { renderTechnicalView } from "@/report/template/technical-view";

// ─── Public API ───────────────────────────────────────────────────────────────

export function renderHtml(
  session: ConformanceSession,
  config?: Config,
): string {
  const data = buildReportData(session, config);

  return `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IT-Wallet Conformance Report</title>
  <style>${REPORT_CSS}</style>
</head>
<body>

  <!-- View switcher -->
  <nav class="view-switcher" aria-label="Seleziona visualizzazione rapporto">
    <button class="view-btn active" id="btn-executive" onclick="switchView('executive')" aria-pressed="true" aria-controls="view-executive">
      <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="M9 12h6M9 16h4M7 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-2M9 4h6a1 1 0 0 1 0 2H9a1 1 0 0 1 0-2Z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Vista Esecutiva
    </button>
    <button class="view-btn" id="btn-technical" onclick="switchView('technical')" aria-pressed="false" aria-controls="view-technical">
      <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="M10 20l4-16M6.343 17.657l-2.829-2.828L1.172 12l2.343-2.343 2.828-2.828M17.657 6.343l2.829 2.828L22.828 12l-2.343 2.343-2.828 2.828" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Vista Tecnica
    </button>
  </nav>

  ${renderExecutiveView(data)}
  ${renderTechnicalView(data)}

  <script>
    function switchView(view) {
      document.querySelectorAll('.view-panel').forEach(function(p) { p.classList.remove('active'); });
      document.querySelectorAll('.view-btn').forEach(function(b) { b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); });
      var panel = document.getElementById('view-' + view);
      var btn   = document.getElementById('btn-' + view);
      if (panel) panel.classList.add('active');
      if (btn)   { btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true'); }
    }
  </script>

</body>
</html>`;
}

// ─── Private: data assembly ───────────────────────────────────────────────────

function buildReportData(
  session: ConformanceSession,
  config?: Config,
): ReportData {
  const { checks } = session;

  const totalChecks = checks.length;
  const passCount = checks.filter((c) => c.result === "PASS").length;
  const failCount = checks.filter((c) => c.result === "FAIL").length;
  const partialCount = checks.filter((c) => c.result === "NOT_REACHED").length;
  const compliancePct =
    totalChecks > 0 ? Math.round((passCount / totalChecks) * 100) : 0;
  const complianceTier = resolveComplianceTier(compliancePct);

  return {
    checkCards: checks.map(renderCheckCard).join("\n"),
    checks,
    compliancePct,
    complianceTier,
    criticalChecks: checks.filter((c) => c.result === "FAIL").slice(0, 5),
    entityName: resolveEntityName(config),
    executedAt: session.startedAt ? formatDateTime(session.startedAt) : "-",
    failCount,
    generatedAt: formatGeneratedAt(new Date().toISOString()),
    partialCount,
    passCount,
    profile: resolveProfile(checks),
    reportId: `WCR-${session.sessionId.toUpperCase().replace(/-/g, "").slice(0, 24)}`,
    sessionId: session.sessionId,
    solutionName: config?.wallet.wallet_name ?? "-",
    specVersion: `Regole Tecniche ${config?.wallet.wallet_version.replace("_", ".")}`,
    statusLabel: resolveTierLabel(complianceTier),
    totalChecks,
    versionPill: `v${readPackageVersion()}`,
  };
}
