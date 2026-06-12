import { writeFileSync } from "node:fs";
import path from "node:path";

import type { ReportView } from "@/report/template/types";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { openDb, resolveDbPath } from "@/report/db";
import { renderPdf } from "@/report/pdf";
import { getLatestSessionId, getSession } from "@/report/session-store";
import { renderHtml } from "@/report/template";

type ReportFormat = "html" | "pdf";

export async function reportCreate(
  runReference: string,
  format: string,
  view = "both",
): Promise<void> {
  assertReportFormat(format);
  assertReportView(view);

  const db = openDb(resolveDbPath());

  try {
    const resolvedRunId =
      runReference === "latest" ? getLatestSessionId(db) : runReference;

    if (!resolvedRunId) {
      console.error("No conformance runs found.");
      process.exit(1);
    }

    const session = getSession(db, resolvedRunId);
    if (!session) {
      console.error(`Conformance run not found: ${runReference}`);
      process.exit(1);
    }

    const config = loadConfigWithHierarchy();
    const html = renderHtml(session, config, view);
    const outputPath = path.resolve(
      process.cwd(),
      `conformance-report-${resolvedRunId}.${format}`,
    );

    if (format === "html") {
      writeFileSync(outputPath, html, "utf8");
      console.log(outputPath);
      return;
    }

    const pdf = await renderPdf(html);
    writeFileSync(outputPath, pdf);
    console.log(outputPath);
  } finally {
    db.close();
  }
}

function assertReportFormat(format: string): asserts format is ReportFormat {
  if (format === "html" || format === "pdf") {
    return;
  }

  throw new Error(
    `Invalid report format: ${format}. Expected one of: html, pdf.`,
  );
}

function assertReportView(view: string): asserts view is ReportView {
  if (view === "both" || view === "executive" || view === "technical") {
    return;
  }

  throw new Error(
    `Invalid report view: ${view}. Expected one of: both, executive, technical.`,
  );
}
