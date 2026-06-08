import type { ConformanceCheck, ConformanceSession } from "@/report/types";
import type { Config } from "@/types";

import { readPackageVersion } from "@/logic/config-loader";

// ─── Types ────────────────────────────────────────────────────────────────────

type ComplianceTier = "failed" | "partial" | "passed";

// ─── Public API ───────────────────────────────────────────────────────────────

/* eslint-disable-next-line max-lines-per-function */
export function renderHtml(
  session: ConformanceSession,
  config?: Config,
): string {
  const { checks } = session;

  const totalChecks = checks.length;
  const passCount = checks.filter((c) => c.result === "PASS").length;
  const compliancePct =
    totalChecks > 0 ? Math.round((passCount / totalChecks) * 100) : 0;

  const complianceTier = resolveComplianceTier(compliancePct);
  const statusLabel = resolveTierLabel(complianceTier);

  const entityName = resolveEntityName(config);
  const solutionName = config?.wallet.wallet_name ?? "-";
  const profile = resolveProfile(checks);
  const versionPill = `v${readPackageVersion()}`;
  const specVersion = `Regole Tecniche ${config?.wallet.wallet_version.replace("_", ".")}`;

  const executedAt = session.startedAt
    ? formatDateTime(session.startedAt)
    : "-";
  const generatedAt = formatGeneratedAt(new Date().toISOString());
  const reportId = `WCR-${session.sessionId.toUpperCase().replace(/-/g, "").slice(0, 24)}`;

  const checkCards = checks.map(renderCheckCard).join("\n");

  const summaryVariantCss =
    complianceTier === "passed"
      ? "summary summary-passed"
      : complianceTier === "failed"
        ? "summary summary-failed"
        : "summary";

  return `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IT-Wallet Conformance Report</title>
  <style>
    :root {
      --ink: #111827;
      --muted: #4b5563;
      --line: #e5e7eb;
      --card: #f9fafb;
      --gold: #ad7f1e;
      --gold-border: #b88322;
      --gold-bg: #fff6dc;
      --green: #1f4a26;
      --green-bg: #e4f3e2;
      --green-border: #61c46b;
      --green-summary-border: #22c55e;
      --green-summary-bg: #dcfce7;
      --red: #7f1d1d;
      --red-bg: #fbdada;
      --red-border: #ff5a5a;
      --yellow: #5f4213;
      --yellow-bg: #fff5d8;
      --yellow-border: #f4b738;
      --detail-bar: #ff5a5a;
      --detail-warn-bar: #fbbf24;
      --radius: 8px;
      font-synthesis-weight: none;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #ffffff;
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, "Helvetica Neue", sans-serif;
      font-size: 14px;
      line-height: 1.35;
    }
    .page {
      width: 100%;
      max-width: 882px;
      min-height: 1162px;
      margin: 0 auto;
      padding: 26px 23px 56px;
      background: #fff;
    }
    .topbar {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 23px;
    }
    .brand { display: flex; align-items: flex-start; gap: 17px; }
    .brand-logo { flex: 0 0 auto; width: 28px; height: 30px; margin-top: 6px; }
    .brand-title {
      margin: 0;
      font-size: 25px;
      line-height: 1.05;
      letter-spacing: -0.03em;
      font-weight: 800;
    }
    .brand-subtitle {
      margin: 3px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.25;
      letter-spacing: -0.01em;
    }
    .version-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 98px;
      min-height: 34px;
      margin-top: 2px;
      border: 1px solid #d7dde6;
      border-radius: 8px;
      background: #fff;
      color: #1f2937;
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0.01em;
    }
    .summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      min-height: 92px;
      padding: 18px 22px 17px 20px;
      border: 1.5px solid var(--gold-border);
      border-radius: var(--radius);
      background: var(--gold-bg);
      color: var(--gold);
    }
    .summary.summary-passed {
      border-color: var(--green-summary-border);
      background: var(--green-summary-bg);
      color: var(--green);
    }
    .summary.summary-failed {
      border-color: var(--red-border);
      background: var(--red-bg);
      color: var(--red);
    }
    .summary-label { margin: 0 0 1px; font-size: 11px; font-weight: 500; opacity: 0.8; }
    .summary-status { margin: 0; font-size: 29px; line-height: 1.06; font-weight: 800; letter-spacing: -0.04em; }
    .summary-score { text-align: right; margin-left: auto; }
    .summary-percent { font-size: 39px; line-height: 0.95; font-weight: 800; letter-spacing: -0.045em; }
    .summary-caption { margin-top: 2px; font-size: 11px; font-weight: 500; opacity: 0.8; }
    .rule { border: 0; border-top: 1px solid var(--line); margin: 19px 0 20px; }
    .section-title {
      display: flex;
      align-items: center;
      gap: 7px;
      margin: 0 0 12px;
      color: var(--ink);
      font-size: 16px;
      line-height: 1.3;
      font-weight: 800;
      letter-spacing: -0.02em;
    }
    .section-title svg { width: 15px; height: 15px; stroke: #111827; }
    .details-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 19px; }
    .info-card { min-height: 65px; padding: 14px 12px 13px; border-radius: 7px; background: var(--card); }
    .info-label {
      display: flex;
      align-items: center;
      gap: 7px;
      margin: 0 0 7px;
      color: #475569;
      font-size: 11px;
      line-height: 1.25;
      font-weight: 500;
    }
    .info-label svg { width: 13px; height: 13px; stroke: #607083; }
    .info-value { margin: 0; color: #111827; font-size: 12px; line-height: 1.35; font-weight: 800; letter-spacing: -0.01em; }
    .checks-title { margin-top: 3px; margin-bottom: 19px; }
    .checks { display: grid; gap: 10px; }
    .check-card { position: relative; border: 1px solid; border-radius: 7px; padding: 13px; overflow: hidden; }
    .check-card.pass { min-height: 76px; border-color: var(--green-border); background: var(--green-bg); color: var(--green); }
    .check-card.fail { border-color: var(--red-border); background: var(--red-bg); color: var(--red); }
    .check-card.partial { border-color: var(--yellow-border); background: var(--yellow-bg); color: var(--yellow); }
    .check-main { display: grid; grid-template-columns: 22px minmax(0, 1fr) auto; align-items: start; gap: 10px; }
    .status-icon { width: 19px; height: 19px; flex: 0 0 auto; }
    .check-line { display: flex; align-items: center; gap: 6px; min-width: 0; padding-top: 1px; }
    .code {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 52px;
      height: 22px;
      padding: 0 6px;
      border-radius: 4px;
      background: #ffffff;
      color: #64748b;
      font-size: 12px;
      line-height: 1;
      font-weight: 800;
      letter-spacing: 0.005em;
      white-space: nowrap;
    }
    .check-title { color: inherit; font-size: 12px; line-height: 1.35; font-weight: 800; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 58px;
      height: 21px;
      padding: 0 6px;
      border: 1px solid currentColor;
      border-radius: 999px;
      background: transparent;
      font-size: 9px;
      line-height: 1;
      font-weight: 800;
      text-transform: uppercase;
      white-space: nowrap;
    }
    .badge.pass-badge    { color: #1f4a26; }
    .badge.fail-badge    { color: #ef1d1d; }
    .badge.partial-badge { color: #6b4a18; }
    .detail-stack { display: grid; gap: 6px; margin: 12px 0 0; }
    .detail-box {
      position: relative;
      min-height: 44px;
      padding: 10px 11px 9px 13px;
      border-radius: 4px;
      background: #ffffff;
      color: #1f2937;
      font-size: 11px;
      line-height: 1.35;
      overflow: hidden;
    }
    .detail-box::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--detail-bar); }
    .partial .detail-box::before { background: var(--detail-warn-bar); }
    .detail-label { display: block; margin-bottom: 4px; color: #334155; font-size: 10px; line-height: 1.2; font-weight: 800; }
    .detail-text { margin: 0; color: #1f2937; font-size: 11px; line-height: 1.35; font-weight: 500; word-break: break-word; }
    .footer { margin-top: 18px; padding-top: 17px; border-top: 1px solid var(--line); color: #475569; font-size: 11px; line-height: 1.4; }
    .footer p { margin: 0 0 8px; }
    .footer .generated { margin-top: 6px; color: #64748b; font-size: 9px; }
    @media (max-width: 720px) {
      .page { min-height: 0; padding: 22px 16px 36px; }
      .brand-title { font-size: 22px; }
      .version-pill { width: 82px; min-height: 32px; }
      .summary { flex-direction: column; min-height: 0; }
      .summary-score { width: 100%; text-align: left; }
      .details-grid { grid-template-columns: 1fr; }
      .check-main { grid-template-columns: 22px minmax(0, 1fr); }
      .badge { grid-column: 2; justify-self: start; margin-top: 4px; }
      .check-title { white-space: normal; }
    }
    @media print {
      body { background: #fff; }
      .page { width: 100%; max-width: none; min-height: 0; padding: 18mm; }
    }
  </style>
</head>
<body>
  <main class="page" aria-label="IT-Wallet Conformance Report">

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
    </header>

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

        <article class="info-card">
          <p class="info-label">ID Sessione</p>
          <p class="info-value">${escapeHtml(session.sessionId)}</p>
        </article>
      </div>
    </section>

    <section aria-labelledby="checks-title">
      <h2 id="checks-title" class="section-title checks-title">Controlli di Conformità Dettagliati</h2>
      <div class="checks">
        ${checkCards}
      </div>
    </section>

    <footer class="footer">
      <p>Questo rapporto è stato generato automaticamente dallo strumento di conformità IT-Wallet.</p>
      <p>ID Rapporto: ${escapeHtml(reportId)}</p>
      <p class="generated">Generato il: ${escapeHtml(generatedAt)}</p>
    </footer>

  </main>
</body>
</html>`;
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDateTime(iso: string): string {
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

function formatGeneratedAt(iso: string): string {
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

function renderCheckCard(check: ConformanceCheck): string {
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

function resolveComplianceTier(pct: number): ComplianceTier {
  if (pct === 100) return "passed";
  if (pct < 50) return "failed";
  return "partial";
}

function resolveEntityName(config?: Config): string {
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

function resolveProfile(checks: ConformanceCheck[]): string {
  const hasIssuance = checks.some((c) => c.phase === "ISSUANCE");
  const hasPresentation = checks.some((c) => c.phase === "PRESENTATION");

  if (hasIssuance && hasPresentation) {
    return "Credential Issuer / Relying Party";
  }

  if (hasPresentation) {
    return "Relying Party (RP)";
  }

  return "Credential Issuer (CI)";
}

function resolveTierLabel(tier: ComplianceTier): string {
  if (tier === "passed") return "Conformità Completa";
  if (tier === "failed") return "Bassa Conformità";
  return "Conformità Parziale";
}
