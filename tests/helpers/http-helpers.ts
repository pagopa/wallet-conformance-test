import { fetchWithConfig, loadConfigWithHierarchy } from "@/logic";

// -----------------------------------------------------------------------
// Helper: POST to response_uri with custom options
// -----------------------------------------------------------------------

export async function postToResponseUri(
  responseUri: string,
  options?: { body?: string; contentType?: string; method?: string },
): Promise<Response> {
  const config = loadConfigWithHierarchy();
  const method = options?.method ?? "POST";
  return fetchWithConfig(config.network)(responseUri, {
    body: ["GET", "HEAD"].includes(method) ? undefined : options?.body,
    headers: {
      "Content-Type":
        options?.contentType ?? "application/x-www-form-urlencoded",
    },
    method,
  });
}
