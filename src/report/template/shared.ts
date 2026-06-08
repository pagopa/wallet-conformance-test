import type { ConformanceCheck } from "@/report/types";

import { escapeHtml } from "@/report/template/helpers";

// ─── Print tab bar ───────────────────────────────────────────────────────────

interface DetailsGridData {
  entityName: string;
  executedAt: string;
  profile: string;
  solutionName: string;
  specVersion: string;
}

// ─── Header ───────────────────────────────────────────────────────────────────

export function renderCheckCard(check: ConformanceCheck): string {
  const { description, errorMessage, httpStatus, requirementId, result } =
    check;

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
    const httpLine =
      httpStatus !== undefined
        ? `<div class="detail-box">
              <span class="detail-label">Stato HTTP:</span>
              <p class="detail-text">${httpStatus}</p>
            </div>`
        : "";

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
          ${httpLine}
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
        <span class="badge partial-badge">NON ESEGUITO</span>
      </div>
      <div class="detail-stack">
        <div class="detail-box">
          <span class="detail-label">Motivo:</span>
          <p class="detail-text">Il controllo non è stato raggiunto durante l'esecuzione del flusso di conformità.</p>
        </div>
      </div>
    </article>`;
}

// ─── Details grid ─────────────────────────────────────────────────────────────

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

export function renderHeader(versionPill: string): string {
  return `
    <header class="topbar">
      <div class="brand">
        <svg class="brand-logo" viewBox="0 0 28 30" aria-hidden="true" focusable="false">
          <path d="M3 4.5 11.5 9v18L3 22.4V4.5Z" fill="#0B6DD8"/>
          <path d="M16.5 2.8 25 7.3v18l-8.5-4.6V2.8Z" fill="#075FCA"/>
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
