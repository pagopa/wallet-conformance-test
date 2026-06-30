import type { Browser } from "puppeteer";

import puppeteer from "puppeteer";

export async function renderPdf(html: string): Promise<Buffer> {
  let browser: Browser | undefined;

  try {
    browser = await puppeteer.launch({ headless: true });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "load" });

    const pdfData = await page.pdf({
      format: "A4",
      printBackground: true,
    });

    return Buffer.from(pdfData);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    throw new Error(
      `Unable to render PDF report: ${message}. Ensure puppeteer's bundled Chromium was downloaded correctly (run "pnpm rebuild puppeteer" if needed).`,
      { cause: error },
    );
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}
