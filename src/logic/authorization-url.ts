import * as cheerio from "cheerio";
import jsQR from "jsqr";
import { PNG } from "pngjs";

import { Config } from "@/types";

export async function fetchAuthorizeRequestUrl(
  presentation: Config["presentation"],
): Promise<string> {
  if (presentation.qr_container_id) {
    const imgSrc = await fetchQrCode(
      presentation.authorize_request_url,
      presentation.qr_container_id,
    );
    return parseQrCode(imgSrc);
  }

  return presentation.authorize_request_url;
}

async function fetchQrCode(url: string, containerId: string) {
  // fetch page HTML
  const response = await fetch(validateUrl(url), {
    method: "GET",
  });
  if (!response.ok) throw new Error(`failed to fetch page: ${url}`);

  // parse DOM
  const html = await response.text();
  const page = cheerio.load(html);

  // find image inside target div
  const imgSrc = page(`${containerId} img`).attr("src");

  if (!imgSrc) throw new Error("QR image not found");

  return imgSrc;
}

async function parseQrCode(image: string): Promise<string> {
  let buffer;

  // handle base64 data URLs
  if (image.startsWith("data:image")) {
    const base64 = image.split(",")[1];
    if (!base64) throw new Error("unable to scan QRCode");

    buffer = Buffer.from(base64, "base64");
  } else {
    const response = await fetch(image, { method: "GET" });

    if (!response.ok) {
      throw new Error(`failed to fetch QRCode from: ${image}`);
    }

    buffer = Buffer.from(await response.arrayBuffer());
  }

  // parse PNG image
  const png = PNG.sync.read(buffer);

  const qr = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  if (!qr) throw new Error("unable to parse QRCode");

  return qr.data;
}

function validateUrl(rawUrl: string): string {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  // allow only http/https
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Unsupported protocol");
  }

  return url.toString();
}
