/**
 * All CSS for the conformance report — shared vars, layout, both views,
 * responsive breakpoints, and print rules.
 */
export const REPORT_CSS = `
  :root {
    --ink: #111827;
    --muted: #4b5563;
    --subtle: #667085;
    --line: #e5e7eb;
    --card: #f9fafb;
    --blue: #0b6dd8;
    --blue-dark: #075fca;
    --gold: #ad7f1e;
    --gold-border: #b88322;
    --gold-bg: #fff6dc;
    --green: #1f4a26;
    --green-bg: #e4f3e2;
    --green-border: #61c46b;
    --green-exec: #2d7d3a;
    --green-exec-bg: #e5f4e5;
    --green-exec-border: #3a8d47;
    --red: #7f1d1d;
    --red-bg: #fbdada;
    --red-border: #ff5a5a;
    --red-exec: #d8333a;
    --red-exec-bg: #ffdddd;
    --red-soft: #fff1f2;
    --red-line: #ffc9ce;
    --amber-exec: #ad7f1e;
    --amber-exec-bg: #fff6dc;
    --amber-exec-border: #b98620;
    --steel: #64748b;
    --steel-bg: #f2f5f9;
    --steel-border: #64748b;
    --yellow: #5f4213;
    --yellow-bg: #fff5d8;
    --yellow-border: #f4b738;
    --detail-bar: #ff5a5a;
    --detail-warn-bar: #fbbf24;
    --radius: 8px;
    font-synthesis-weight: none;
  }

  /* ── Reset ── */
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: #ffffff;
    color: var(--ink);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
      "Segoe UI", Roboto, Arial, "Helvetica Neue", sans-serif;
    font-size: 14px;
    line-height: 1.35;
  }

  /* ── View switcher ── */
  .view-switcher {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px 0 0;
    max-width: 882px;
    margin: 0 auto;
  }
  .view-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 20px;
    border: 1.5px solid #d7dde6;
    background: #f9fafb;
    color: #64748b;
    font-family: inherit;
    font-size: 13px;
    font-weight: 700;
    line-height: 1;
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
    user-select: none;
    position: relative;
  }
  .view-btn:first-child { border-radius: 8px 0 0 8px; }
  .view-btn:last-child  { border-radius: 0 8px 8px 0; margin-left: -1.5px; }
  .view-btn.active { background: #ffffff; color: var(--blue); border-color: var(--blue); z-index: 1; }
  .view-btn svg { width: 14px; height: 14px; stroke: currentColor; fill: none; }

  /* ── View panels ── */
  .page {
    width: 100%;
    max-width: 882px;
    min-height: 1050px;
    margin: 0 auto;
    padding: 26px 23px 56px;
    background: #fff;
  }
  .view-panel { display: none; }
  .view-panel.active { display: block; }

  /* ── Shared: header ── */
  .topbar {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
    margin-bottom: 23px;
  }
  .brand { display: flex; align-items: flex-start; gap: 17px; }
  .brand-logo { flex: 0 0 auto; width: 28px; height: 30px; margin-top: 6px; }
  .brand-title { margin: 0; font-size: 25px; line-height: 1.05; letter-spacing: -0.03em; font-weight: 800; }
  .brand-subtitle { margin: 3px 0 0; color: var(--muted); font-size: 13px; line-height: 1.25; letter-spacing: -0.01em; }
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

  /* ── Shared: misc ── */
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
  .footer { margin-top: 18px; padding-top: 17px; border-top: 1px solid var(--line); color: #475569; font-size: 11px; line-height: 1.4; }
  .footer p { margin: 0 0 8px; }
  .footer .generated { margin-top: 6px; color: #64748b; font-size: 9px; }

  /* ── Shared: compliance banner ── */
  .compliance-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    min-height: 92px;
    padding: 18px 22px 17px 20px;
    border: 1.5px solid;
    border-radius: var(--radius);
  }
  .compliance-banner--passed  { border-color: var(--green-exec-border); background: var(--green-exec-bg); color: var(--green-exec); }
  .compliance-banner--failed  { border-color: var(--red-exec);          background: var(--red-exec-bg);   color: var(--red-exec); }
  .compliance-banner--partial { border-color: var(--amber-exec-border); background: var(--amber-exec-bg); color: var(--amber-exec); }
  .banner-eyebrow { margin: 0 0 1px; font-size: 11px; font-weight: 500; opacity: 0.8; }
  .banner-status  { margin: 0; font-size: 29px; line-height: 1.06; font-weight: 800; letter-spacing: -0.04em; }
  .banner-score   { text-align: right; margin-left: auto; }
  .banner-percent { font-size: 39px; line-height: 0.95; font-weight: 800; letter-spacing: -0.045em; }
  .banner-caption { margin-top: 2px; font-size: 11px; font-weight: 500; opacity: 0.8; }

  /* ── Technical view: check cards ── */
  .checks-title { margin-top: 3px; margin-bottom: 19px; }
  .checks { display: grid; gap: 10px; }
  .check-card { position: relative; border: 1px solid; border-radius: 7px; padding: 13px; overflow: hidden; }
  .check-card.pass    { min-height: 76px; border-color: var(--green-border); background: var(--green-bg); color: var(--green); }
  .check-card.fail    { border-color: var(--red-border); background: var(--red-bg); color: var(--red); }
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

  /* ── Executive view: metrics grid ──

  .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 12px 0 17px; }
  .metric-card { min-height: 74px; border: 1.5px solid; border-radius: var(--radius); padding: 13px 16px 12px; }
  .metric-card.total   { color: var(--steel);     border-color: var(--steel-border);       background: var(--steel-bg); }
  .metric-card.passed  { color: var(--green-exec); border-color: var(--green-exec-border); background: var(--green-exec-bg); }
  .metric-card.partial { color: var(--amber-exec); border-color: var(--amber-exec-border); background: var(--amber-exec-bg); }
  .metric-card.failed  { color: var(--red-exec);   border-color: var(--red-exec);          background: var(--red-exec-bg); }
  .metric-label { display: block; margin-bottom: 2px; font-size: 12px; line-height: 1.2; font-weight: 800; }
  .metric-value { display: block; font-size: 28px; line-height: 1; font-weight: 800; letter-spacing: -0.04em; }

  /* ── Executive view: narrative ── */
  .executive-title { margin: 16px 0 12px; color: var(--ink); font-size: 16px; line-height: 1.3; font-weight: 800; letter-spacing: -0.02em; }
  .executive-copy { margin: 0 0 15px; color: #334155; font-size: 13px; line-height: 1.55; font-weight: 400; }
  .executive-copy + .executive-copy { margin-top: 3px; }
  .critical-box { margin-top: 14px; padding: 14px 12px 18px; border: 1px solid var(--red-line); border-radius: 7px; background: var(--red-soft); }
  .critical-title { margin: 0 0 9px; color: #e00008; font-size: 12px; line-height: 1.35; font-weight: 800; }
  .critical-list { display: grid; gap: 6px; margin: 0; padding: 0; list-style: none; }
  .critical-list li { min-height: 34px; padding: 8px 18px; background: #ffffff; color: #e00008; font-size: 12px; line-height: 1.35; font-weight: 800; }

  /* ── Responsive ── */
  @media (max-width: 720px) {
    .page { min-height: 0; padding: 22px 16px 36px; }
    .brand-title { font-size: 22px; }
    .version-pill { width: 82px; min-height: 32px; }
    .compliance-banner { flex-direction: column; align-items: flex-start; min-height: 0; }
    .banner-score { width: 100%; text-align: left; margin-left: 0; }
    .details-grid, .metrics { grid-template-columns: 1fr; }
    .check-main { grid-template-columns: 22px minmax(0, 1fr); }
    .badge { grid-column: 2; justify-self: start; margin-top: 4px; }
    .check-title { white-space: normal; }
  }

  /* ── Print: hide switcher, show both views stacked ── */
  /* ── Print-only tab bar (anchor links, shown once per view section) ── */
  .print-tab-bar { display: none; }

  @media print {
    .print-tab-bar {
      display: flex;
      margin-bottom: 18px;
    }
    .print-tab-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 18px;
      border: 1.5px solid #d7dde6;
      background: #f9fafb;
      color: #64748b;
      font-family: inherit;
      font-size: 12px;
      font-weight: 700;
      line-height: 1;
      text-decoration: none;
      position: relative;
    }
    .print-tab-btn:first-child { border-radius: 8px 0 0 8px; }
    .print-tab-btn:last-child  { border-radius: 0 8px 8px 0; margin-left: -1.5px; }
    .print-tab-btn.active { background: #ffffff; color: var(--blue); border-color: var(--blue); z-index: 1; }
    .print-tab-btn svg { width: 13px; height: 13px; stroke: currentColor; fill: none; }
  }

  /* ── Avoid mid-card page breaks (screen + print) ── */
  .check-card,
  .info-card,
  .metric-card,
  .critical-box,
  .detail-box {
    break-inside: avoid;
    page-break-inside: avoid; /* legacy Webkit/Chromium fallback */
  }

  @page { margin: 18mm; }

  @media print {
    body { background: #fff; }
    .view-switcher { display: none; }
    .view-panel { display: block !important; }
    .page { width: 100%; max-width: none; min-height: 0; padding: 0; }
    .view-panel + .view-panel { page-break-before: always; }
  }
`;
