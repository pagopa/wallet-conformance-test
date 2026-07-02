import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { Config } from "@/types";

const execFileAsync = promisify(execFile);

export async function getAuthorizeRequestUrl(
  presentation: Config["presentation"],
): Promise<string> {
  if (presentation.authorize_request_script) {
    try {
      const { stdout } = await execFileAsync(
        presentation.authorize_request_script,
        [],
        { encoding: "utf8" },
      );

      return parseAuthorizeRequestUrl(
        stdout,
        presentation.authorize_request_script,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Authorize request script ${presentation.authorize_request_script} failed: ${message}`,
      );
    }
  }

  return presentation.authorize_request_url;
}

function parseAuthorizeRequestUrl(output: string, scriptPath: string): string {
  const authorizeRequestUrl = output.trim();

  if (!authorizeRequestUrl) {
    throw new Error(
      `Authorize request script ${scriptPath} did not output a URL`,
    );
  }

  try {
    new URL(authorizeRequestUrl);
    return authorizeRequestUrl;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Authorize request script ${scriptPath} output an invalid URL: ${message}`,
    );
  }
}
