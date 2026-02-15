import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2022",
    platform: "node",
    outDir: "dist"
  },
  {
    entry: ["src/cli.ts"],
    format: ["cjs"],
    dts: false,
    sourcemap: true,
    clean: false,
    target: "es2022",
    platform: "node",
    outDir: "dist",
    banner: { js: "#!/usr/bin/env node" }
  }
]);
