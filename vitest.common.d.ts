export function buildIncludePattern(
  testType: string,
  testsDir: string,
  userConfigured: boolean,
): string;

export function buildExcludePatterns(runsBuiltTests: boolean): string[];

export function createTestConfig(
  testType: string,
): import("vitest/config").UserConfig;

export function resolveConfigPath(launchDir?: string, rootDir?: string): string;
