import { readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const rootDir = new URL("../..", import.meta.url);

const suites = ["runtime/tests", "typescript-sdk/tests"];

function getTestFiles(relativeDir) {
  const absoluteDir = new URL(relativeDir, rootDir);
  return readdirSync(absoluteDir)
    .filter((file) => file.endsWith(".test.mjs"))
    .map((file) => path.posix.join(relativeDir, file));
}

for (const suite of suites) {
  const files = getTestFiles(suite);
  if (files.length === 0) {
    continue;
  }
  const run = spawnSync("node", ["--test", ...files], {
    stdio: "inherit",
    cwd: rootDir
  });
  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
