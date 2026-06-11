import type { ComplianceTier } from "@/report/template/types";
import type { ConformanceCheck } from "@/report/types";

import { escapeHtml } from "@/report/template/helpers";

// ─── Compliance banner ───────────────────────────────────────────────────────

interface ComplianceBannerData {
  compliancePct: number;
  complianceTier: ComplianceTier;
  statusLabel: string;
}

interface DetailsGridData {
  entityName: string;
  executedAt: string;
  profile: string;
  solutionName: string;
  specVersion: string;
}

// ─── Footer ───────────────────────────────────────────────────────────────────

interface FooterData {
  generatedAt: string;
  reportId: string;
  sessionId?: string;
}

export function renderCheckCard(check: ConformanceCheck): string {
  const { description, errorMessage, requirementId, result } = check;

  if (result === "PASS") {
    return `
      <article class="check-card pass">
        <div class="check-main">
          <svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <circle cx="12" cy="12" r="11" fill="#1F4A26"/>
            <path d="m7.5 12 3 3 6-7" fill="none" stroke="#fff" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          <div>
            <div class="check-line">
              <span class="code">${escapeHtml(requirementId)}</span>
              <span class="check-title">${escapeHtml(description)}</span>
            </div>
          </div>
          <span class="badge pass-badge">SUPERATO</span>
        </div>
      </article>`;
  }

  if (result === "FAIL") {
    const problemText = escapeHtml(
      errorMessage ?? "Verifica fallita senza dettagli di errore.",
    );
    return `
      <article class="check-card fail">
        <div class="check-main">
          <svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M10.3 3.5h3.4L22 18.5 20.2 21H3.8L2 18.5 10.3 3.5Z" fill="#7F1D1D"/>
            <path d="M12 8v5" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>
            <circle cx="12" cy="17" r="1.2" fill="#fff"/>
          </svg>
          <div>
            <div class="check-line">
              <span class="code">${escapeHtml(requirementId)}</span>
              <span class="check-title">${escapeHtml(description)}</span>
            </div>
          </div>
          <span class="badge fail-badge">FALLITO</span>
        </div>
        <div class="detail-stack">
          <div class="detail-box">
            <span class="detail-label">Problema Identificato:</span>
            <p class="detail-text">${problemText}</p>
          </div>
        </div>
      </article>`;
  }

  // NOT_REACHED → partial / yellow
  return `
    <article class="check-card partial">
      <div class="check-main">
        <svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
          <path d="M10.3 3.5h3.4L22 18.5 20.2 21H3.8L2 18.5 10.3 3.5Z" fill="#5F4213"/>
          <path d="M12 8v5" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>
          <circle cx="12" cy="17" r="1.2" fill="#fff"/>
        </svg>
        <div>
          <div class="check-line">
            <span class="code">${escapeHtml(requirementId)}</span>
            <span class="check-title">${escapeHtml(description)}</span>
          </div>
        </div>
        <span class="badge partial-badge">PARZIALE</span>
      </div>
      <div class="detail-stack">
        <div class="detail-box">
          <span class="detail-label">Motivo:</span>
          <p class="detail-text">Il controllo non è stato raggiunto durante l'esecuzione del flusso di conformità.</p>
        </div>
      </div>
    </article>`;
}

// ─── Print tab bar ───────────────────────────────────────────────────────────

export function renderComplianceBanner({
  compliancePct,
  complianceTier,
  statusLabel,
}: ComplianceBannerData): string {
  return `
    <section class="compliance-banner compliance-banner--${complianceTier}" aria-label="Stato di conformità complessivo">
      <div>
        <p class="banner-eyebrow">Stato di Conformità Complessivo</p>
        <p class="banner-status">${escapeHtml(statusLabel)}</p>
      </div>
      <div class="banner-score" aria-label="Tasso di conformità ${compliancePct} percento">
        <div class="banner-percent">${compliancePct}%</div>
        <div class="banner-caption">Tasso di Conformità</div>
      </div>
    </section>`;
}

// ─── Header ───────────────────────────────────────────────────────────────────

export function renderDetailsGrid(data: DetailsGridData): string {
  const { entityName, executedAt, profile, solutionName, specVersion } = data;

  return `
    <section aria-labelledby="details-title">
      <h2 id="details-title" class="section-title">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
          <path d="M9 4h6l1.3 2H19a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h2.7L9 4Z" stroke-width="2" stroke-linejoin="round"/>
          <path d="M9 6h6M8 11h8M8 15h8M8 19h5" stroke-width="2" stroke-linecap="round"/>
        </svg>
        Dettagli del test
      </h2>

      <div class="details-grid">
        <article class="info-card">
          <p class="info-label">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
              <path d="M4 20h16M6 20V9l6-4 6 4v11M9 20v-7h6v7M9 10h.01M12 10h.01M15 10h.01" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            Ente
          </p>
          <p class="info-value">${escapeHtml(entityName)}</p>
        </article>

        <article class="info-card">
          <p class="info-label">Nome della soluzione</p>
          <p class="info-value">${escapeHtml(solutionName)}</p>
        </article>

        <article class="info-card">
          <p class="info-label">Profilo</p>
          <p class="info-value">${escapeHtml(profile)}</p>
        </article>

        <article class="info-card">
          <p class="info-label">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
              <path d="M7 3v4M17 3v4M4 9h16M6 5h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            Data e ora dell'esecuzione
          </p>
          <p class="info-value">${escapeHtml(executedAt)}</p>
        </article>

        <article class="info-card">
          <p class="info-label">Versione delle regole tecniche</p>
          <p class="info-value">${escapeHtml(specVersion)}</p>
        </article>
      </div>
    </section>`;
}

// ─── Details grid ─────────────────────────────────────────────────────────────

export function renderFooter({
  generatedAt,
  reportId,
  sessionId,
}: FooterData): string {
  const sessionLine =
    sessionId !== undefined
      ? `<p>ID Sessione: ${escapeHtml(sessionId)}</p>`
      : "";
  return `
    <footer class="footer">
      <p>Questo rapporto è stato generato automaticamente dallo strumento di conformità IT-Wallet.</p>
      <p>ID Rapporto: ${escapeHtml(reportId)}</p>
      ${sessionLine}
      <p class="generated">Generato il: ${escapeHtml(generatedAt)}</p>
    </footer>`;
}

export function renderHeader(versionPill: string): string {
  return `
    <header class="topbar">
      <div class="brand">
      <svg width="30" height="36" viewBox="0 0 30 36" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M14.1526 0.177162C13.9351 0.0535781 13.7039 -0.00134806 13.4796 2.50963e-05C12.771 0.00551771 12.1212 0.575376 12.1253 1.36906L12.165 8.63578L2.05052 2.94132C1.83165 2.81773 1.60047 2.76281 1.37613 2.76418C0.667548 2.76967 0.0232548 3.33953 0.0218868 4.13322L0 28.0837C0 29.1644 0.484246 30.1064 1.52113 30.69L10.6137 35.8228C10.8326 35.9464 11.0638 36.0014 11.2881 36C11.9967 35.9945 12.6424 35.4246 12.6424 34.6309V10.0707L17.4493 12.7566C18.4875 13.3361 18.9704 14.2822 18.9704 15.3629V29.7535L27.9618 34.8163C28.1807 34.9399 28.4118 34.9948 28.6362 34.9935C29.3448 34.988 29.9904 34.4181 29.9904 33.6244L30 10.8507C30 9.77001 29.5158 8.82802 28.4789 8.24444L14.1526 0.177162Z" fill="#0066CC"/>
      </svg>
        <div>
          <h1 class="brand-title">IT-Wallet Conformance Report</h1>
          <p class="brand-subtitle">Risultato della verifica di conformità tecnica</p>
        </div>
      </div>
      <div class="version-pill">${escapeHtml(versionPill)}</div>
    </header>`;
}

// ─── Check card ───────────────────────────────────────────────────────────────

/**
 * Renders a print-only tab bar with anchor links so readers can jump between
 * the executive and technical sections within the same PDF.
 * Hidden on screen; visible only via @media print.
 */
export function renderPrintTabBar(
  activeView: "executive" | "technical",
): string {
  const execActive = activeView === "executive";

  const execBtn = execActive
    ? `<span class="print-tab-btn active" aria-current="page">
        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
          <path d="M9 12h6M9 16h4M7 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-2M9 4h6a1 1 0 0 1 0 2H9a1 1 0 0 1 0-2Z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Vista Esecutiva
      </span>`
    : `<a class="print-tab-btn" href="#view-executive">
        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
          <path d="M9 12h6M9 16h4M7 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-2M9 4h6a1 1 0 0 1 0 2H9a1 1 0 0 1 0-2Z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Vista Esecutiva
      </a>`;

  const techBtn = !execActive
    ? `<span class="print-tab-btn active" aria-current="page">
        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
          <path d="M10 20l4-16M6.343 17.657l-2.829-2.828L1.172 12l2.343-2.343 2.828-2.828M17.657 6.343l2.829 2.828L22.828 12l-2.343 2.343-2.828 2.828" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Vista Tecnica
      </span>`
    : `<a class="print-tab-btn" href="#view-technical">
        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
          <path d="M10 20l4-16M6.343 17.657l-2.829-2.828L1.172 12l2.343-2.343 2.828-2.828M17.657 6.343l2.829 2.828L22.828 12l-2.343 2.343-2.828 2.828" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Vista Tecnica
      </a>`;

  return `
    <nav class="print-tab-bar" aria-label="Seleziona visualizzazione rapporto">
      ${execBtn}
      ${techBtn}
    </nav>`;
}
