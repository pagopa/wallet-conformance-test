import type { ReportData } from "@/report/template/types";

import { escapeHtml } from "@/report/template/helpers";
import {
  renderDetailsGrid,
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

  const summaryVariantCss =
    complianceTier === "passed"
      ? "summary summary-passed"
      : complianceTier === "failed"
        ? "summary summary-failed"
        : "summary";

  return `
  <div id="view-technical" class="view-panel" role="region" aria-label="Vista Tecnica">
    <main class="page" aria-label="IT-Wallet Conformance Report - Vista Tecnica">

      ${showPrintTabBar ? renderPrintTabBar("technical") : ""}
      ${renderHeader(versionPill)}

      <section class="${summaryVariantCss}" aria-label="Stato di conformità complessivo">
        <div>
          <p class="summary-label">Stato di Conformità Complessivo</p>
          <p class="summary-status">${escapeHtml(statusLabel)}</p>
        </div>
        <div class="summary-score" aria-label="Tasso di conformità ${compliancePct} percento">
          <div class="summary-percent">${compliancePct}%</div>
          <div class="summary-caption">Tasso di Conformità</div>
        </div>
      </section>

      <hr class="rule"/>

      ${renderDetailsGrid({ entityName, executedAt, profile, solutionName, specVersion })}

      <section aria-labelledby="checks-title">
        <h2 id="checks-title" class="section-title checks-title">Controlli di Conformità Dettagliati</h2>
        <div class="checks">
          ${checkCards}
        </div>
      </section>

      <footer class="footer">
        <p>Questo rapporto è stato generato automaticamente dallo strumento di conformità IT-Wallet.</p>
        <p>ID Rapporto: ${escapeHtml(reportId)}</p>
        <p>ID Sessione: ${escapeHtml(sessionId)}</p>
        <p class="generated">Generato il: ${escapeHtml(generatedAt)}</p>
      </footer>

    </main>
  </div>`;
}
