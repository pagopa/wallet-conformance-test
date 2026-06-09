import type { ReportData } from "@/report/template/types";

import {
  renderComplianceBanner,
  renderDetailsGrid,
  renderFooter,
  renderHeader,
  renderPrintTabBar,
} from "@/report/template/shared";

// ─── Technical view ───────────────────────────────────────────────────────────

export function renderTechnicalView(
  data: ReportData,
  showPrintTabBar = false,
): string {
  const {
    checkCards,
    compliancePct,
    complianceTier,
    entityName,
    executedAt,
    generatedAt,
    profile,
    reportId,
    sessionId,
    solutionName,
    specVersion,
    statusLabel,
    versionPill,
  } = data;

  return `
  <div id="view-technical" class="view-panel" role="region" aria-label="Vista Tecnica">
    <main class="page" aria-label="IT-Wallet Conformance Report - Vista Tecnica">

      ${showPrintTabBar ? renderPrintTabBar("technical") : ""}
      ${renderHeader(versionPill)}

      ${renderComplianceBanner({ compliancePct, complianceTier, statusLabel })}

      <hr class="rule"/>

      ${renderDetailsGrid({ entityName, executedAt, profile, solutionName, specVersion })}

      <section aria-labelledby="checks-title">
        <h2 id="checks-title" class="section-title checks-title">Controlli di Conformità Dettagliati</h2>
        <div class="checks">
          ${checkCards}
        </div>
      </section>

      ${renderFooter({ generatedAt, reportId, sessionId })}

    </main>
  </div>`;
}
