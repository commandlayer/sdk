import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const suites = [
  "runtime/tests",
  "typescript-sdk/tests"
];

for (const suiteDir of suites) {
  const absoluteSuiteDir = path.join(repoRoot, suiteDir);

  if (!existsSync(absoluteSuiteDir)) {
    continue;
  }

  const matchedFiles = readdirSync(absoluteSuiteDir)
    .filter((fileName) => fileName.endsWith(".test.mjs"))
    .map((fileName) => path.join(suiteDir, fileName));

  if (matchedFiles.length === 0) {
    continue;
  }

  const run = spawnSync("node", ["--test", ...matchedFiles], {
    stdio: "inherit",
    cwd: repoRoot
  });

  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
