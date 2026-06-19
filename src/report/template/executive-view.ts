import type { ReportData } from "@/report/template/types";

import { escapeHtml } from "@/report/template/helpers";
import {
  renderComplianceBanner,
  renderDetailsGrid,
  renderFooter,
  renderHeader,
  renderPrintTabBar,
} from "@/report/template/shared";

// ─── Executive view ───────────────────────────────────────────────────────────

export function renderExecutiveView(
  data: ReportData,
  showPrintTabBar = false,
): string {
  const {
    compliancePct,
    complianceTier,
    criticalChecks,
    entityName,
    executedAt,
    failCount,
    generatedAt,
    partialCount,
    passCount,
    profile,
    reportId,
    solutionName,
    specVersion,
    statusLabel,
    totalChecks,
    versionPill,
  } = data;

  const narrative1 = `${escapeHtml(entityName)} ha eseguito una verifica di conformità per ${escapeHtml(solutionName)} (profilo ${escapeHtml(profile)}) secondo le ${escapeHtml(specVersion)} il ${escapeHtml(executedAt)}.`;

  const passVerb = passCount === 1 ? "è stato superato" : "sono stati superati";
  const partialVerb =
    partialCount === 1
      ? "è parzialmente conforme"
      : "sono parzialmente conformi";
  const failVerb = failCount === 1 ? "è fallito" : "sono falliti";
  const narrative2 = `Su ${totalChecks} controlli di conformità, ${passCount} ${passVerb} con successo, ${partialCount} ${partialVerb} e ${failCount} ${failVerb}.<br/>Questo porta a un tasso di conformità del ${compliancePct}% e a uno stato complessivo di ${escapeHtml(statusLabel)}.`;

  const criticalBox =
    criticalChecks.length > 0
      ? `<aside class="critical-box" aria-labelledby="critical-title">
          <h3 id="critical-title" class="critical-title">Problemi critici che richiedono un'azione correttiva:</h3>
          <ul class="critical-list">
            ${criticalChecks.map((c) => `<li>${escapeHtml(c.description)}</li>`).join("\n            ")}
          </ul>
        </aside>`
      : "";

  return `
  <div id="view-executive" class="view-panel active" role="region" aria-label="Vista Esecutiva">
    <main class="page" aria-label="IT-Wallet Conformance Report - Vista Esecutiva">

      ${showPrintTabBar ? renderPrintTabBar("executive") : ""}
      ${renderHeader(versionPill)}

      ${renderComplianceBanner({ compliancePct, complianceTier, statusLabel })}

      <hr class="rule"/>

      ${renderDetailsGrid({ entityName, executedAt, profile, solutionName, specVersion })}

      <section aria-labelledby="validation-title">
        <h2 id="validation-title" class="section-title">Riepilogo Validazione</h2>
        <div class="metrics" aria-label="Riepilogo dei controlli di validazione">
          <article class="metric-card total">
            <span class="metric-label">Controlli Totali</span>
            <span class="metric-value">${totalChecks}</span>
          </article>
          <article class="metric-card passed">
            <span class="metric-label">Superati</span>
            <span class="metric-value">${passCount}</span>
          </article>
          <article class="metric-card partial">
            <span class="metric-label">Parziali</span>
            <span class="metric-value">${partialCount}</span>
          </article>
          <article class="metric-card failed">
            <span class="metric-label">Falliti</span>
            <span class="metric-value">${failCount}</span>
          </article>
        </div>
      </section>

      <section aria-labelledby="executive-summary-title">
        <h2 id="executive-summary-title" class="executive-title">Sintesi Esecutiva</h2>
        <p class="executive-copy">${narrative1}</p>
        <p class="executive-copy">${narrative2}</p>
        ${criticalBox}
      </section>

      ${renderFooter({ generatedAt, reportId })}

    </main>
  </div>`;
}
