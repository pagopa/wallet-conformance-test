import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "path";

const DUMPS_PREFIX_RE = /^\.?\/?dumps(?:\/|$)/;

function findPackageRoot(startDir: string): string {
  let current = startDir;

  while (true) {
    if (existsSync(path.join(current, "package.json"))) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return startDir;
    }
    current = parent;
  }
}

export const packageRoot = findPackageRoot(
  path.dirname(fileURLToPath(import.meta.url)),
);

export const packageAssetsRoot = packageRoot;

export function readPackageVersion(): string {
  try {
    const pkgPath = path.resolve(packageRoot, "package.json");
    const content = readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(content) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

export function resolveConfigRelativePath(
  relativePath: string,
  baseDir = packageRoot,
): string {
  const normalized = relativePath.replace(/\\/g, "/");

  if (DUMPS_PREFIX_RE.test(normalized)) {
    return resolvePackageAssetPath(normalized);
  }

  return resolvePathFrom(baseDir, normalized);
}

export function resolveDefaultConfigPath(): string {
  return path.join(packageRoot, "config.example.ini");
}

export function resolveLocalConfigPath(
  workspaceDir = process.cwd(),
  rootDir = packageRoot,
): null | string {
  const workspaceConfigPath = path.resolve(workspaceDir, "config.ini");
  if (existsSync(workspaceConfigPath)) {
    return workspaceConfigPath;
  }

  const packageConfigPath = path.join(rootDir, "config.ini");
  if (existsSync(packageConfigPath)) {
    return packageConfigPath;
  }

  return null;
}

export function resolvePackageAssetPath(relativePath: string): string {
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }

  return path.resolve(packageAssetsRoot, relativePath);
}

export function resolvePathFrom(baseDir: string, relativePath: string): string {
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }

  return path.resolve(baseDir, relativePath);
}

export function resolveWorkspacePath(relativePath: string): string {
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }

  return path.resolve(process.cwd(), relativePath);
}
