import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = new URL("../..", import.meta.url);
const repoRootPath = fileURLToPath(repoRoot);

const suites = [
  { dir: "runtime/tests", optional: true },
  { dir: "typescript-sdk/tests", optional: false }
];

for (const suite of suites) {
  const suitePath = path.join(repoRootPath, suite.dir);

  if (!existsSync(suitePath)) {
    if (suite.optional) {
      continue;
    }
    console.error(`Missing required test directory: ${suite.dir}`);
    process.exit(1);
  }

  const testFiles = readdirSync(suitePath)
    .filter((name) => name.endsWith(".test.mjs"))
    .sort()
    .map((name) => path.join(suite.dir, name));

  if (testFiles.length === 0) {
    if (suite.optional) {
      continue;
    }
    console.error(`No required test files found in: ${suite.dir}`);
    process.exit(1);
  }

  for (const testFile of testFiles) {
    const run = spawnSync("node", ["--test", testFile], {
      stdio: "inherit",
      cwd: repoRoot
    });

    if (run.status !== 0) {
      process.exit(run.status ?? 1);
    }
  }
}
