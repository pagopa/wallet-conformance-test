import { pathToFileURL } from "node:url";

export const isMainModule = (metaUrl: string): boolean => {
  const entrypoint = process.argv[1];
  return (
    typeof entrypoint === "string" && pathToFileURL(entrypoint).href === metaUrl
  );
};
