import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

const suiteDirs = [
  path.join(repoRoot, "runtime", "tests"),
  path.join(repoRoot, "typescript-sdk", "tests")
];

const testFiles = suiteDirs
  .flatMap((dir) => {
    if (!existsSync(dir)) {
      return [];
    }

    return readdirSync(dir)
      .filter((entry) => entry.endsWith(".test.mjs"))
      .sort()
      .map((entry) => path.join(path.relative(repoRoot, dir), entry));
  });

if (testFiles.length === 0) {
  console.error("No .test.mjs files found in runtime/tests or typescript-sdk/tests");
  process.exit(1);
}

const run = spawnSync("node", ["--test", ...testFiles], {
  stdio: "inherit",
  cwd: repoRoot
});

if (run.status !== 0) {
  process.exit(run.status ?? 1);
}
