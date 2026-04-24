import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const suites = [
  { dir: "runtime/tests", optional: true },
  { dir: "typescript-sdk/tests", optional: false }
];

for (const suite of suites) {
  const suiteDir = join(repoRoot, suite.dir);
  if (!existsSync(suiteDir)) {
    if (suite.optional) {
      continue;
    }
    console.error(`Required test suite directory is missing: ${suite.dir}`);
    process.exit(1);
  }

  const suiteFiles = readdirSync(suiteDir)
    .filter((file) => file.endsWith(".test.mjs"))
    .sort()
    .map((file) => join(suite.dir, file));

  if (suiteFiles.length === 0) {
    if (suite.optional) {
      continue;
    }
    console.error(`No test files found in required suite: ${suite.dir}`);
    process.exit(1);
  }

  const run = spawnSync("node", ["--test", ...suiteFiles], {
    stdio: "inherit",
    cwd: repoRoot
  });
  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
