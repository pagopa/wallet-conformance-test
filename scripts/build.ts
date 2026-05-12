import * as esbuild from "esbuild";
import { glob } from "glob";
import { rm } from "node:fs/promises";

const production = process.argv.includes("--production");

await rm("dist", { force: true, recursive: true });

const common = {
  bundle: true,
  format: "esm",
  logLevel: "info",
  platform: "node",
  sourcemap: !production,
  target: "node22",
  tsconfig: "tsconfig.json",
} satisfies esbuild.BuildOptions;

await esbuild.build({
  ...common,
  entryPoints: ["src/cli.ts"],
  outfile: "dist/cli.js",
  packages: "external",
});

const testEntryPoints = await glob(
  [
    "tests/conformance/**/*.spec.ts",
    "tests/global-setup.ts",
    "tests/setup-tls.ts",
  ],
  { windowsPathsNoEscape: true },
);

await esbuild.build({
  ...common,
  entryNames: "[dir]/[name]",
  entryPoints: testEntryPoints,
  external: ["vitest"],
  outbase: ".",
  outdir: "dist",
  packages: "external",
});
