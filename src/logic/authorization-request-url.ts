import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { Config } from "@/types";

const execFileAsync = promisify(execFile);

export async function getAuthorizeRequestUrl(
  presentation: Config["presentation"],
): Promise<string> {
  const script = presentation.authorize_request_script;
  if (script) {
    return await runAuthorizeRequestScript(script);
  }

  return presentation.authorize_request_url;
}

function parseAuthorizeRequestUrl(output: string, script: string): string {
  const authorizeRequestUrl = output.trim();

  if (!authorizeRequestUrl) {
    throw new Error(`Authorize request script ${script} did not output a URL`);
  }

  try {
    new URL(authorizeRequestUrl);
    return authorizeRequestUrl;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Authorize request script ${script} output an invalid URL: ${message}`,
    );
  }
}

async function runAuthorizeRequestScript(script: string) {
  try {
    const { stdout } = await execFileAsync(script, [], {
      encoding: "utf8",
      timeout: 15_000,
    });

    return parseAuthorizeRequestUrl(stdout, script);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Authorize request script ${script} failed: ${message}`);
  }
}
